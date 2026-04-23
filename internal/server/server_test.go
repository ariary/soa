package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/pkg/checkapi"
)

func newTestServerWithRules(t *testing.T, rules config.RulesConfig, upstreamTime time.Time) (*Server, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"Version": "v1.0.0",
			"Time":    upstreamTime.Format(time.RFC3339),
		})
	}))
	t.Cleanup(upstream.Close)

	cachePath := filepath.Join(t.TempDir(), "approved.json")
	s := NewServer(rules, cachePath, upstream.URL)
	return s, httptest.NewServer(s.Handler())
}

func newTestServer(t *testing.T, maxAgeDays int, upstreamTime time.Time) (*Server, *httptest.Server) {
	t.Helper()
	return newTestServerWithRules(t, config.RulesConfig{
		MaxAge: config.MaxAgeRule{Enabled: true, MinDays: maxAgeDays},
	}, upstreamTime)
}

func TestCheckAllowed_OldPackage(t *testing.T) {
	s, srv := newTestServer(t, 7, time.Now().AddDate(0, -1, 0))
	defer srv.Close()
	_ = s

	body, _ := json.Marshal(checkapi.CheckRequest{Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusAllowed {
		t.Errorf("expected allowed for old package, got %s: %s", cr.Status, cr.Reason)
	}
}

func TestCheckBlocked_NewPackage(t *testing.T) {
	s, srv := newTestServer(t, 7, time.Now().Add(-2*24*time.Hour))
	defer srv.Close()
	_ = s

	body, _ := json.Marshal(checkapi.CheckRequest{Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusBlocked {
		t.Errorf("expected blocked for new package, got %s", cr.Status)
	}
	if cr.Reason == "" {
		t.Error("expected a reason for blocking")
	}
}

func TestCheckCacheHit(t *testing.T) {
	s, srv := newTestServer(t, 7, time.Now().AddDate(0, -1, 0))
	defer srv.Close()
	_ = s

	req := checkapi.CheckRequest{Module: "github.com/foo/bar", Version: "v1.0.0"}
	body, _ := json.Marshal(req)

	resp, _ := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	resp.Body.Close()

	body, _ = json.Marshal(req)
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusAllowed {
		t.Errorf("expected cache hit allowed, got %s", cr.Status)
	}
}

func TestCachePersistence(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "approved.json")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"Version": "v1.0.0",
			"Time":    time.Now().AddDate(0, -1, 0).Format(time.RFC3339),
		})
	}))
	defer upstream.Close()

	rules := config.RulesConfig{MaxAge: config.MaxAgeRule{Enabled: true, MinDays: 7}}
	s1 := NewServer(rules, cachePath, upstream.URL)
	srv1 := httptest.NewServer(s1.Handler())

	body, _ := json.Marshal(checkapi.CheckRequest{Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, _ := http.Post(srv1.URL+"/check", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	srv1.Close()

	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache file should exist: %v", err)
	}

	s2 := NewServer(rules, cachePath, upstream.URL)
	if !s2.isCached("github.com/foo/bar", "v1.0.0") {
		t.Error("expected cache entry to survive restart")
	}
}

func TestMaxAgeDisabled_AllowsNewPackage(t *testing.T) {
	// A 2-day-old package would normally be blocked with minDays=7,
	// but with max_age disabled it should be allowed.
	rules := config.RulesConfig{
		MaxAge: config.MaxAgeRule{Enabled: false, MinDays: 7},
	}
	_, srv := newTestServerWithRules(t, rules, time.Now().Add(-2*24*time.Hour))
	defer srv.Close()

	body, _ := json.Marshal(checkapi.CheckRequest{Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusAllowed {
		t.Errorf("expected allowed when max_age disabled, got %s: %s", cr.Status, cr.Reason)
	}
}

func TestBothRulesDisabled_Passthrough(t *testing.T) {
	// When both rules are disabled, everything should pass through.
	rules := config.RulesConfig{
		MaxAge:   config.MaxAgeRule{Enabled: false},
		Analysis: config.AnalysisRule{Enabled: false},
	}
	_, srv := newTestServerWithRules(t, rules, time.Now().Add(-1*time.Hour))
	defer srv.Close()

	body, _ := json.Marshal(checkapi.CheckRequest{Module: "github.com/brand-new/pkg", Version: "v0.0.1"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusAllowed {
		t.Errorf("expected passthrough allowed, got %s: %s", cr.Status, cr.Reason)
	}
}
