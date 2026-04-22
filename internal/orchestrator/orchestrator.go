package orchestrator

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/ariary/soa/internal/check"
	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/internal/proxy"
	"github.com/ariary/soa/internal/ui"
)

func Run(cfg config.Config, managers []manager.Manager, args []string, env []string, isTTY bool) int {
	port := cfg.Proxy.Port
	if port == 0 {
		port = freePort()
	}
	proxyAddr := fmt.Sprintf("http://localhost:%d", port)

	var activeManagers []proxy.ActiveManager
	for _, m := range managers {
		upstream, active := m.Detect(env)
		if !active {
			continue
		}
		env = m.InjectEnv(env, proxyAddr)
		activeManagers = append(activeManagers, proxy.ActiveManager{
			Manager:  m,
			Upstream: upstream,
		})
	}

	if len(activeManagers) == 0 {
		fmt.Fprintf(os.Stderr, "[soa] warning: no ecosystems detected, running as transparent passthrough\n")
	}

	client := check.NewClient(cfg.CheckURL, cfg.CheckTimeout, cfg.PollInterval)
	spinner := ui.NewSpinner(os.Stderr, !isTTY)

	p := proxy.New(activeManagers, client, spinner)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := p.ListenAndServe(ctx, port); err != nil {
			fmt.Fprintf(os.Stderr, "[soa] proxy error: %v\n", err)
		}
	}()

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				cmd.Process.Signal(sig)
			}
		}
	}()

	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			fmt.Fprintf(os.Stderr, "[soa] error: %v\n", err)
			exitCode = 1
		}
	}

	cancel()
	spinner.Shutdown()
	signal.Stop(sigCh)

	return exitCode
}

func freePort() int {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 8080
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
