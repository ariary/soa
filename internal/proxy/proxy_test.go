package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ariary/soa/internal/check"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/internal/ui"
	"github.com/ariary/soa/pkg/checkapi"
)

func TestProxyForwardsNonZipTransparently(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"v1.0.0","Time":"2020-01-01T00:00:00Z"}`))
	}))
	defer upstream.Close()

	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("check server should not be called for .info requests")
	}))
	defer checkSrv.Close()

	gm := &manager.GolangManager{}
	client := check.NewClient(checkSrv.URL, 5*time.Second, 100*time.Millisecond)
	spinner := ui.NewSpinner(io.Discard, true)

	p := New([]ActiveManager{{Manager: gm, Upstream: upstream.URL}}, client, spinner)
	srv := httptest.NewServer(p)
	defer srv.Close()
	defer spinner.Shutdown()

	resp, err := http.Get(srv.URL + "/github.com/foo/bar/@v/v1.0.0.info")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) == "" {
		t.Error("expected non-empty body")
	}
}

func TestProxyChecksZipAndAllows(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fake-zip-content"))
	}))
	defer upstream.Close()

	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
	}))
	defer checkSrv.Close()

	gm := &manager.GolangManager{}
	client := check.NewClient(checkSrv.URL, 5*time.Second, 100*time.Millisecond)
	spinner := ui.NewSpinner(io.Discard, true)

	p := New([]ActiveManager{{Manager: gm, Upstream: upstream.URL}}, client, spinner)
	srv := httptest.NewServer(p)
	defer srv.Close()
	defer spinner.Shutdown()

	resp, err := http.Get(srv.URL + "/github.com/foo/bar/@v/v1.0.0.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "fake-zip-content" {
		t.Errorf("expected upstream content, got %s", string(body))
	}
}

func TestProxyChecksZipAndBlocks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should-not-reach-client"))
	}))
	defer upstream.Close()

	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{
			Status: checkapi.StatusBlocked,
			Reason: "too new",
		})
	}))
	defer checkSrv.Close()

	gm := &manager.GolangManager{}
	client := check.NewClient(checkSrv.URL, 5*time.Second, 100*time.Millisecond)
	spinner := ui.NewSpinner(io.Discard, true)

	p := New([]ActiveManager{{Manager: gm, Upstream: upstream.URL}}, client, spinner)
	srv := httptest.NewServer(p)
	defer srv.Close()
	defer spinner.Shutdown()

	resp, err := http.Get(srv.URL + "/github.com/foo/bar/@v/v1.0.0.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxyUnmatchedRequestReturns404(t *testing.T) {
	spinner := ui.NewSpinner(io.Discard, true)
	p := New([]ActiveManager{}, nil, spinner)
	srv := httptest.NewServer(p)
	defer srv.Close()
	defer spinner.Shutdown()

	resp, err := http.Get(srv.URL + "/random/path")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}
