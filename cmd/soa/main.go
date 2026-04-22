package main

import (
	"fmt"
	"os"

	"github.com/ariary/quicli/pkg/quicli"
	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/internal/orchestrator"
	"github.com/ariary/soa/internal/server"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: soa <command> [args...] or soa serve [--port]")
		os.Exit(1)
	}

	if os.Args[1] == "serve" {
		serveCmd()
		return
	}

	proxyCmd()
}

func serveCmd() {
	cli := quicli.Cli{
		Usage:       "soa serve [flags]",
		Description: "Start the soa reference check server",
		Flags: quicli.Flags{
			{Name: "port", Default: 0, Description: "port to listen on (overrides config)"},
		},
	}

	os.Args = append(os.Args[:1], os.Args[2:]...)
	cfg_parsed := cli.Parse()

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
	if dir := expandedCachePath[:len(expandedCachePath)-len("/approved.json")]; dir != "" {
		os.MkdirAll(dir, 0755)
	}

	fmt.Fprintf(os.Stderr, "[soa] check server starting on :%d\n", cfg.Server.Port)
	s := server.NewServer(cfg.Server.MaxAgeDays, expandedCachePath, "https://proxy.golang.org")
	if err := s.ListenAndServe(cfg.Server.Port); err != nil {
		fmt.Fprintf(os.Stderr, "[soa] server error: %v\n", err)
		os.Exit(1)
	}
}

func proxyCmd() {
	cfg := config.Load()

	disableGo := false
	cmdStart := 1

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--go=false":
			disableGo = true
			cmdStart = i + 1
		default:
			cmdStart = i
			goto done
		}
	}
done:

	if cmdStart >= len(os.Args) {
		fmt.Fprintln(os.Stderr, "Usage: soa [--go=false] <command> [args...]")
		os.Exit(1)
	}

	args := os.Args[cmdStart:]

	var managers []manager.Manager
	if !disableGo {
		managers = append(managers, &manager.GolangManager{})
	}

	isTTY := term.IsTerminal(int(os.Stderr.Fd()))

	exitCode := orchestrator.Run(cfg, managers, args, os.Environ(), isTTY)
	os.Exit(exitCode)
}
