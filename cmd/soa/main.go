package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ariary/quicli/pkg/quicli"
	"github.com/ariary/soa/internal/analyzer"
	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/internal/feed"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/internal/orchestrator"
	"github.com/ariary/soa/internal/provider"
	"github.com/ariary/soa/internal/server"
	"golang.org/x/term"
)

func main() {
	cli := quicli.Cli{
		Usage:       "soa [flags] <command> [args...]",
		Description: "Your packages go through customs now",
		Flags: quicli.Flags{
			{Name: "verbose", Default: false, Description: "show allowed packages (only blocked are shown by default)"},
			{Name: "go", Default: true, Description: "intercept Go package downloads"},
			{Name: "npm", Default: true, Description: "intercept npm package downloads"},
			{Name: "pip", Default: true, Description: "intercept pip package downloads"},
			{Name: "rubygems", Default: true, Description: "intercept RubyGems downloads"},
			{Name: "port", Default: 0, Description: "port to listen on (overrides config)", NotForRootCommand: true, SharedSubcommand: quicli.SubcommandSet{"serve"}},
			{Name: "interval", Default: "5m", Description: "feed polling interval", NotForRootCommand: true, SharedSubcommand: quicli.SubcommandSet{"feed"}},
			{Name: "ecosystem", Default: "", Description: "filter by ecosystem (npm,pypi,go,rubygems)", NotForRootCommand: true, SharedSubcommand: quicli.SubcommandSet{"feed"}},
		},
		Function: proxyCmd,
		Subcommands: quicli.Subcommands{
			{Name: "serve", Description: "Start the soa reference check server", Function: serveCmd},
			{Name: "feed", Description: "Live feed of malicious package advisories from osv.dev", Function: feedCmd},
		},
	}

	cli.RunWithSubcommand()
}

func serveCmd(cfg_parsed quicli.Config) {
	cfg := config.Load()

	port := cfg_parsed.GetIntFlag("port")
	if port != 0 {
		cfg.Server.Port = port
	}

	expandedCachePath := cfg.Server.CachePath
	if len(expandedCachePath) > 0 && expandedCachePath[0] == '~' {
		home, _ := os.UserHomeDir()
		expandedCachePath = home + expandedCachePath[1:]
	}

	// Ensure cache directory exists
	if dir := filepath.Dir(expandedCachePath); dir != "" {
		os.MkdirAll(dir, 0755)
	}

	upstreams := map[string]string{
		"go":       "https://proxy.golang.org",
		"npm":      "https://registry.npmjs.org",
		"pip":      "https://pypi.org",
		"rubygems": "https://rubygems.org",
	}

	fmt.Fprintf(os.Stderr, "[soa] check server starting on :%d\n", cfg.Server.Port)
	s := server.NewServer(cfg.Server.Rules, expandedCachePath, upstreams)

	if cfg.Server.Rules.Analysis.Enabled {
		llm, err := provider.New(cfg.Server.Rules.Analysis)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[soa] provider error: %v\n", err)
			os.Exit(1)
		}
		githubToken := ""
		if cfg.Server.Rules.Analysis.GitHubTokenEnv != "" {
			githubToken = os.Getenv(cfg.Server.Rules.Analysis.GitHubTokenEnv)
		}
		codeAnalyzer := analyzer.NewCodeAnalyzer(llm, upstreams, cfg.Server.Rules.Analysis.MaxSourceBytes)
		releaseAnalyzer := analyzer.NewReleaseAnalyzer(llm, "", githubToken, upstreams)
		s.SetAnalyzers([]analyzer.Analyzer{codeAnalyzer, releaseAnalyzer})
		fmt.Fprintf(os.Stderr, "[soa] analysis enabled (provider: %s, model: %s)\n", llm.Name(), cfg.Server.Rules.Analysis.Model)
	}

	if err := s.ListenAndServe(cfg.Server.Port); err != nil {
		fmt.Fprintf(os.Stderr, "[soa] server error: %v\n", err)
		os.Exit(1)
	}
}

func proxyCmd(cfg_parsed quicli.Config) {
	cfg := config.Load()

	verbose := cfg_parsed.GetBoolFlag("verbose")
	enableGo := cfg_parsed.GetBoolFlag("go")

	args := cfg_parsed.Args
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: soa [flags] <command> [args...]")
		os.Exit(1)
	}

	enableNpm := cfg_parsed.GetBoolFlag("npm")
	enablePip := cfg_parsed.GetBoolFlag("pip")
	enableRubyGems := cfg_parsed.GetBoolFlag("rubygems")

	var managers []manager.Manager
	if enableGo {
		managers = append(managers, &manager.GolangManager{})
	}
	if enableNpm {
		managers = append(managers, &manager.NpmManager{})
	}
	if enablePip {
		managers = append(managers, &manager.PipManager{})
	}
	if enableRubyGems {
		managers = append(managers, &manager.RubyGemsManager{})
	}

	isTTY := term.IsTerminal(int(os.Stderr.Fd()))

	exitCode := orchestrator.Run(cfg, managers, args, os.Environ(), isTTY, verbose)
	os.Exit(exitCode)
}

func feedCmd(cfg_parsed quicli.Config) {
	intervalStr := cfg_parsed.GetStringFlag("interval")
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[soa] invalid interval %q: %v\n", intervalStr, err)
		os.Exit(1)
	}

	var ecosystems []string
	if eco := cfg_parsed.GetStringFlag("ecosystem"); eco != "" {
		ecosystems = strings.Split(eco, ",")
	}

	home, _ := os.UserHomeDir()
	statePath := home + "/.config/soa/feed-state.json"

	// Ensure state directory exists
	if dir := filepath.Dir(statePath); dir != "" {
		os.MkdirAll(dir, 0755)
	}

	isTTY := term.IsTerminal(int(os.Stderr.Fd()))

	// Resolve GitHub token for GHSA feed (optional)
	appCfg := config.Load()
	githubToken := ""
	if appCfg.Server.Rules.Analysis.GitHubTokenEnv != "" {
		githubToken = os.Getenv(appCfg.Server.Rules.Analysis.GitHubTokenEnv)
	}
	if githubToken == "" {
		githubToken = os.Getenv("GITHUB_TOKEN")
	}

	cfg := feed.Config{
		Interval:    interval,
		Ecosystems:  ecosystems,
		StatePath:   statePath,
		GithubToken: githubToken,
	}

	sources := "osv.dev"
	if githubToken != "" {
		sources += " + GHSA"
	}
	fmt.Fprintf(os.Stderr, "[soa] feed started (polling every %s, sources: %s)\n", interval, sources)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := feed.Run(ctx, cfg, os.Stdout, !isTTY); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "[soa] feed error: %v\n", err)
		os.Exit(1)
	}
}
