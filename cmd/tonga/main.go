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
	"github.com/ariary/soa/internal/provider"
	"github.com/ariary/soa/internal/server"
	"golang.org/x/term"
)

func main() {
	cli := quicli.Cli{
		Usage:       "tonga <command> [flags]",
		Description: "soa server & feed — the backend half of your package customs",
		Flags: quicli.Flags{
			{Name: "port", Default: 0, Description: "port to listen on (overrides config)", SharedSubcommand: quicli.SubcommandSet{"serve"}},
			{Name: "interval", Default: "5m", Description: "feed polling interval", SharedSubcommand: quicli.SubcommandSet{"feed"}},
			{Name: "ecosystem", Default: "", Description: "filter by ecosystem (npm,pypi,go,rubygems)", SharedSubcommand: quicli.SubcommandSet{"feed"}},
			{Name: "source", Default: "all", Description: "data sources: all, osv, ghsa (comma-separated)", SharedSubcommand: quicli.SubcommandSet{"feed"}},
			{Name: "since", Default: "24h", Description: "initial lookback window (e.g. 30m, 4h, 7d, 1M, 1y)", SharedSubcommand: quicli.SubcommandSet{"feed"}},
			{Name: "info", Default: "default", Description: "output detail level: short, default, full", SharedSubcommand: quicli.SubcommandSet{"feed"}},
			{Name: "field", Default: []string{}, Description: "extra fields to include in output (repeatable: --field details --field severity)", SharedSubcommand: quicli.SubcommandSet{"feed"}},
		},
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

	// Resolve GitHub token for GHSA malware checks
	serverGithubToken := ""
	if cfg.Server.Rules.Analysis.GitHubTokenEnv != "" {
		serverGithubToken = os.Getenv(cfg.Server.Rules.Analysis.GitHubTokenEnv)
	}
	if serverGithubToken == "" {
		serverGithubToken = os.Getenv("GITHUB_TOKEN")
	}

	fmt.Fprintf(os.Stderr, "[tonga] check server starting on :%d\n", cfg.Server.Port)
	s := server.NewServer(cfg.Server.Rules, expandedCachePath, upstreams)

	if serverGithubToken != "" {
		s.SetGithubToken(serverGithubToken)
		fmt.Fprintf(os.Stderr, "[tonga] known malware check: osv.dev + GHSA\n")
	} else {
		fmt.Fprintf(os.Stderr, "[tonga] known malware check: osv.dev (set GITHUB_TOKEN to enable GHSA)\n")
	}

	if cfg.Server.Rules.Analysis.Enabled {
		llm, err := provider.New(cfg.Server.Rules.Analysis)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[tonga] provider error: %v\n", err)
			os.Exit(1)
		}
		githubToken := ""
		if cfg.Server.Rules.Analysis.GitHubTokenEnv != "" {
			githubToken = os.Getenv(cfg.Server.Rules.Analysis.GitHubTokenEnv)
		}
		codeAnalyzer := analyzer.NewCodeAnalyzer(llm, upstreams, cfg.Server.Rules.Analysis.MaxSourceBytes)
		releaseAnalyzer := analyzer.NewReleaseAnalyzer(llm, "", githubToken, upstreams)
		s.SetAnalyzers([]analyzer.Analyzer{codeAnalyzer, releaseAnalyzer})
		fmt.Fprintf(os.Stderr, "[tonga] analysis enabled (provider: %s, model: %s)\n", llm.Name(), cfg.Server.Rules.Analysis.Model)
	}

	if err := s.ListenAndServe(cfg.Server.Port); err != nil {
		fmt.Fprintf(os.Stderr, "[tonga] server error: %v\n", err)
		os.Exit(1)
	}
}

// parseSince parses a lookback duration string. It supports Go durations (30m, 4h)
// plus d (days), M (months), and y (years) suffixes.
func parseSince(s string) (time.Time, error) {
	if len(s) == 0 {
		return time.Time{}, fmt.Errorf("empty duration")
	}
	suffix := s[len(s)-1]
	numStr := s[:len(s)-1]
	switch suffix {
	case 'd':
		n, err := parseInt(numStr)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid days %q: %w", s, err)
		}
		return time.Now().AddDate(0, 0, -n), nil
	case 'M':
		n, err := parseInt(numStr)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid months %q: %w", s, err)
		}
		return time.Now().AddDate(0, -n, 0), nil
	case 'y':
		n, err := parseInt(numStr)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid years %q: %w", s, err)
		}
		return time.Now().AddDate(-n, 0, 0), nil
	default:
		d, err := time.ParseDuration(s)
		if err != nil {
			return time.Time{}, err
		}
		return time.Now().Add(-d), nil
	}
}

func parseInt(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	if len(s) == 0 {
		return 0, fmt.Errorf("empty number")
	}
	return n, nil
}

func feedCmd(cfg_parsed quicli.Config) {
	intervalStr := cfg_parsed.GetStringFlag("interval")
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[tonga] invalid interval %q: %v\n", intervalStr, err)
		os.Exit(1)
	}

	sinceStr := cfg_parsed.GetStringFlag("since")
	sinceTime, err := parseSince(sinceStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[tonga] invalid --since %q: %v\n", sinceStr, err)
		os.Exit(1)
	}

	var ecosystems []string
	if eco := cfg_parsed.GetStringFlag("ecosystem"); eco != "" {
		ecosystems = strings.Split(eco, ",")
	}

	// Parse --source flag
	var sources []string
	if src := cfg_parsed.GetStringFlag("source"); src != "" {
		for _, s := range strings.Split(src, ",") {
			s = strings.TrimSpace(strings.ToLower(s))
			switch s {
			case "all", "osv", "ghsa":
				sources = append(sources, s)
			default:
				fmt.Fprintf(os.Stderr, "[tonga] unknown source %q (valid: all, osv, ghsa)\n", s)
				os.Exit(1)
			}
		}
	}
	// "all" is the default and expands to both
	wantOSV := len(sources) == 0
	wantGHSA := len(sources) == 0
	for _, s := range sources {
		switch s {
		case "all":
			wantOSV = true
			wantGHSA = true
		case "osv":
			wantOSV = true
		case "ghsa":
			wantGHSA = true
		}
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

	// Warn if GHSA is requested but no token
	if wantGHSA && githubToken == "" {
		fmt.Fprintf(os.Stderr, "[tonga] warning: GHSA source selected but GITHUB_TOKEN is not set; GHSA feed will be skipped\n")
	}

	// Parse --info flag
	var infoLevel feed.InfoLevel
	switch strings.ToLower(cfg_parsed.GetStringFlag("info")) {
	case "short":
		infoLevel = feed.InfoShort
	case "default", "":
		infoLevel = feed.InfoDefault
	case "full":
		infoLevel = feed.InfoFull
	default:
		fmt.Fprintf(os.Stderr, "[tonga] unknown --info level %q (valid: short, default, full)\n", cfg_parsed.GetStringFlag("info"))
		os.Exit(1)
	}

	cfg := feed.Config{
		Interval:    interval,
		Ecosystems:  ecosystems,
		StatePath:   statePath,
		GithubToken: githubToken,
		EnableOSV:   wantOSV,
		EnableGHSA:  wantGHSA,
		Since:       sinceTime,
		InfoLevel:   infoLevel,
		OSVFields:   cfg_parsed.GetStringSliceFlag("field"),
	}

	var sourceLabel string
	switch {
	case wantOSV && wantGHSA:
		sourceLabel = "osv.dev + GHSA"
	case wantOSV:
		sourceLabel = "osv.dev"
	case wantGHSA:
		sourceLabel = "GHSA"
	}
	fmt.Fprintf(os.Stderr, "[tonga] feed started (polling every %s, sources: %s)\n", interval, sourceLabel)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := feed.Run(ctx, cfg, os.Stdout, !isTTY); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "[tonga] feed error: %v\n", err)
		os.Exit(1)
	}
}
