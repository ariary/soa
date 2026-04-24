package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

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
	managers  []ActiveManager
	client    *check.Client
	spinner   *ui.Spinner
	mux       *http.ServeMux
	proxyAddr string
}

func New(managers []ActiveManager, client *check.Client, spinner *ui.Spinner, proxyAddr string) *Proxy {
	p := &Proxy{
		managers:  managers,
		client:    client,
		spinner:   spinner,
		mux:       http.NewServeMux(),
		proxyAddr: proxyAddr,
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

		upstreamURL := am.Manager.UpstreamURL(am.Upstream, r)
		if rw, ok := am.Manager.(manager.ResponseRewriter); ok {
			p.forwardWithRewrite(w, r, upstreamURL, rw)
		} else {
			p.forward(w, r, upstreamURL)
		}
		return
	}

	http.NotFound(w, r)
}

func (p *Proxy) checkPackage(ctx context.Context, w http.ResponseWriter, pkg manager.PackageRequest) bool {
	p.spinner.Start(pkg.Module, pkg.Version)

	resp, err := p.client.CheckWithProgress(ctx, checkapi.CheckRequest{
		Ecosystem: pkg.Ecosystem,
		Module:    pkg.Module,
		Version:   pkg.Version,
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

func (p *Proxy) forwardWithRewrite(w http.ResponseWriter, r *http.Request, upstreamURL string, rw manager.ResponseRewriter) {
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	body = rw.RewriteResponse(r, body, p.proxyAddr)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
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
