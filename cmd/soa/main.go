package main

import (
	"fmt"
	"os"

	"github.com/ariary/quicli/pkg/quicli"
	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/internal/orchestrator"
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
		},
		Function: proxyCmd,
	}

	cli.Run()
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
