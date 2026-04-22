package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/ariary/soa/internal/check"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/internal/ui"
	"github.com/ariary/soa/pkg/checkapi"
)

type ActiveManager struct {
	Manager  manager.Manager
	Upstream string
}

type Proxy struct {
	managers []ActiveManager
	client   *check.Client
	spinner  *ui.Spinner
	mux      *http.ServeMux
}

func New(managers []ActiveManager, client *check.Client, spinner *ui.Spinner) *Proxy {
	p := &Proxy{
		managers: managers,
		client:   client,
		spinner:  spinner,
		mux:      http.NewServeMux(),
	}
	p.mux.HandleFunc("/", p.handle)
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mux.ServeHTTP(w, r)
}

func (p *Proxy) ListenAndServe(ctx context.Context, port int) error {
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: p,
	}

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", srv.Addr, err)
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	err = srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	for _, am := range p.managers {
		if !am.Manager.Match(r) {
			continue
		}

		pkg, err := am.Manager.Parse(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if pkg.NeedsCheck() {
			if !p.checkPackage(r.Context(), w, pkg) {
				return
			}
		}

		p.forwardWithChain(w, r, am)
		return
	}

	http.NotFound(w, r)
}

func (p *Proxy) checkPackage(ctx context.Context, w http.ResponseWriter, pkg manager.PackageRequest) bool {
	p.spinner.Start(pkg.Module, pkg.Version)

	resp, err := p.client.CheckWithProgress(ctx, checkapi.CheckRequest{
		Module:  pkg.Module,
		Version: pkg.Version,
	}, func(progress float64) {
		p.spinner.SetProgress(pkg.Module, progress)
	})

	if err != nil {
		p.spinner.Stop(pkg.Module, false, "check error: "+err.Error())
		http.Error(w, "package blocked: check error", http.StatusForbidden)
		return false
	}

	if resp.Status == checkapi.StatusBlocked {
		p.spinner.Stop(pkg.Module, false, resp.Reason)
		http.Error(w, fmt.Sprintf("package blocked: %s", resp.Reason), http.StatusForbidden)
		return false
	}

	p.spinner.Stop(pkg.Module, true, "")
	return true
}

func (p *Proxy) forwardWithChain(w http.ResponseWriter, r *http.Request, am ActiveManager) {
	gm, ok := am.Manager.(*manager.GolangManager)
	if !ok {
		upstreamURL := am.Manager.UpstreamURL(am.Upstream, r)
		p.forward(w, r, upstreamURL)
		return
	}

	entries := gm.ParseUpstreamChain(am.Upstream)

	for _, entry := range entries {
		if entry.IsDirect || entry.IsOff {
			continue
		}

		upstreamURL := strings.TrimRight(entry.URL, "/") + r.URL.Path
		statusCode, respBody, respHeaders := p.tryForward(r, upstreamURL)

		shouldFallback := false
		if entry.FallbackOnError && statusCode == 0 {
			shouldFallback = true
		} else if (entry.FallbackOnNotFound || entry.FallbackOnError) && (statusCode == http.StatusNotFound || statusCode == http.StatusGone) {
			shouldFallback = true
		} else if entry.FallbackOnError && statusCode >= 400 {
			shouldFallback = true
		}

		if shouldFallback {
			if respBody != nil {
				respBody.Close()
			}
			continue
		}

		if statusCode == 0 {
			http.Error(w, "upstream unreachable", http.StatusBadGateway)
			return
		}

		for k, vv := range respHeaders {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(statusCode)
		if respBody != nil {
			io.Copy(w, respBody)
			respBody.Close()
		}
		return
	}

	http.NotFound(w, r)
}

func (p *Proxy) tryForward(r *http.Request, upstreamURL string) (int, io.ReadCloser, http.Header) {
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		return 0, nil, nil
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, nil
	}

	return resp.StatusCode, resp.Body, resp.Header
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, upstreamURL string) {
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
