package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ariary/soa/internal/analyzer"
	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/pkg/checkapi"
)

func newTestServerWithVersions(t *testing.T, rules config.RulesConfig, upstreamTime time.Time, numVersions int) (*Server, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/@v/list") {
			for i := range numVersions {
				fmt.Fprintf(w, "v1.0.%d\n", i)
			}
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"Version": "v1.0.0",
			"Time":    upstreamTime.Format(time.RFC3339),
		})
	}))
	t.Cleanup(upstream.Close)

	cachePath := filepath.Join(t.TempDir(), "approved.json")
	upstreams := map[string]string{"go": upstream.URL}
	s := NewServer(rules, cachePath, upstreams)
	return s, httptest.NewServer(s.Handler())
}

func newTestServerWithRules(t *testing.T, rules config.RulesConfig, upstreamTime time.Time) (*Server, *httptest.Server) {
	t.Helper()
	return newTestServerWithVersions(t, rules, upstreamTime, 10)
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

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/foo/bar", Version: "v1.0.0"})
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

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/foo/bar", Version: "v1.0.0"})
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

	req := checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/foo/bar", Version: "v1.0.0"}
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
	s1 := NewServer(rules, cachePath, map[string]string{"go": upstream.URL})
	srv1 := httptest.NewServer(s1.Handler())

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, _ := http.Post(srv1.URL+"/check", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	srv1.Close()

	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache file should exist: %v", err)
	}

	s2 := NewServer(rules, cachePath, map[string]string{"go": upstream.URL})
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

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/foo/bar", Version: "v1.0.0"})
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

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/brand-new/pkg", Version: "v0.0.1"})
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

// --- mock analyzer for analysis tests ---

type mockTestAnalyzer struct {
	result analyzer.AnalysisResult
}

func (m *mockTestAnalyzer) Name() string { return "mock" }
func (m *mockTestAnalyzer) Analyze(ctx context.Context, req analyzer.AnalysisRequest) (analyzer.AnalysisResult, error) {
	return m.result, nil
}

func TestAnalysisEnabled_ReturnsProcessing(t *testing.T) {
	rules := config.RulesConfig{
		MaxAge:   config.MaxAgeRule{Enabled: true, MinDays: 7},
		Analysis: config.AnalysisRule{Enabled: true},
	}
	// Package published 6 months ago — passes max_age check.
	s, srv := newTestServerWithRules(t, rules, time.Now().AddDate(0, -6, 0))
	defer srv.Close()

	s.SetAnalyzers([]analyzer.Analyzer{
		&mockTestAnalyzer{result: analyzer.AnalysisResult{Block: false, Summary: "clean"}},
	})

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusProcessing {
		t.Errorf("expected processing, got %s: %s", cr.Status, cr.Reason)
	}
	if cr.ID == "" {
		t.Error("expected non-empty job ID")
	}
}

func TestPollJobStatus(t *testing.T) {
	rules := config.RulesConfig{
		MaxAge:   config.MaxAgeRule{Enabled: true, MinDays: 7},
		Analysis: config.AnalysisRule{Enabled: true},
	}
	s, srv := newTestServerWithRules(t, rules, time.Now().AddDate(0, -6, 0))
	defer srv.Close()

	s.SetAnalyzers([]analyzer.Analyzer{
		&mockTestAnalyzer{result: analyzer.AnalysisResult{Block: false, Summary: "clean"}},
	})

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	resp.Body.Close()

	if cr.Status != checkapi.StatusProcessing {
		t.Fatalf("expected processing, got %s", cr.Status)
	}
	jobID := cr.ID

	// Poll until the job completes.
	var finalStatus string
	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		pollResp, err := http.Get(srv.URL + "/check/" + jobID)
		if err != nil {
			t.Fatal(err)
		}
		var pollCR checkapi.CheckResponse
		json.NewDecoder(pollResp.Body).Decode(&pollCR)
		pollResp.Body.Close()
		if pollCR.Status != checkapi.StatusProcessing {
			finalStatus = pollCR.Status
			break
		}
	}

	if finalStatus != checkapi.StatusAllowed {
		t.Errorf("expected allowed after polling, got %s", finalStatus)
	}
}

func TestPollJobBlocked(t *testing.T) {
	rules := config.RulesConfig{
		MaxAge:   config.MaxAgeRule{Enabled: true, MinDays: 7},
		Analysis: config.AnalysisRule{Enabled: true},
	}
	s, srv := newTestServerWithRules(t, rules, time.Now().AddDate(0, -6, 0))
	defer srv.Close()

	s.SetAnalyzers([]analyzer.Analyzer{
		&mockTestAnalyzer{result: analyzer.AnalysisResult{Block: true, Summary: "suspicious code found"}},
	})

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	resp.Body.Close()

	if cr.Status != checkapi.StatusProcessing {
		t.Fatalf("expected processing, got %s", cr.Status)
	}
	jobID := cr.ID

	var finalStatus string
	var finalReason string
	for i := 0; i < 50; i++ {
		time.Sleep(10 * time.Millisecond)
		pollResp, err := http.Get(srv.URL + "/check/" + jobID)
		if err != nil {
			t.Fatal(err)
		}
		var pollCR checkapi.CheckResponse
		json.NewDecoder(pollResp.Body).Decode(&pollCR)
		pollResp.Body.Close()
		if pollCR.Status != checkapi.StatusProcessing {
			finalStatus = pollCR.Status
			finalReason = pollCR.Reason
			break
		}
	}

	if finalStatus != checkapi.StatusBlocked {
		t.Errorf("expected blocked after polling, got %s", finalStatus)
	}
	if finalReason == "" {
		t.Error("expected a reason for blocking")
	}
}

func TestPollJob_NotFound(t *testing.T) {
	rules := config.RulesConfig{}
	_, srv := newTestServerWithRules(t, rules, time.Now())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/check/nonexistent-id")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestMinVersions_BlocksLowCount(t *testing.T) {
	rules := config.RulesConfig{
		MinVersions: config.MinVersionsRule{Enabled: true, Count: 2},
	}
	_, srv := newTestServerWithVersions(t, rules, time.Now().AddDate(0, -6, 0), 1)
	defer srv.Close()

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/new/pkg", Version: "v0.0.1"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusBlocked {
		t.Errorf("expected blocked for module with 1 version, got %s", cr.Status)
	}
	if cr.Reason == "" {
		t.Error("expected a reason for blocking")
	}
}

func TestMinVersions_AllowsExactCount(t *testing.T) {
	rules := config.RulesConfig{
		MinVersions: config.MinVersionsRule{Enabled: true, Count: 2},
	}
	_, srv := newTestServerWithVersions(t, rules, time.Now().AddDate(0, -6, 0), 2)
	defer srv.Close()

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusAllowed {
		t.Errorf("expected allowed when version count equals minimum, got %s: %s", cr.Status, cr.Reason)
	}
}

func TestMinVersions_Disabled(t *testing.T) {
	rules := config.RulesConfig{
		MinVersions: config.MinVersionsRule{Enabled: false, Count: 2},
	}
	_, srv := newTestServerWithVersions(t, rules, time.Now().AddDate(0, -6, 0), 1)
	defer srv.Close()

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/new/pkg", Version: "v0.0.1"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusAllowed {
		t.Errorf("expected allowed when min_versions disabled, got %s: %s", cr.Status, cr.Reason)
	}
}

func TestMinVersions_FailClosed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/@v/list") {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"Version": "v1.0.0",
			"Time":    time.Now().AddDate(0, -6, 0).Format(time.RFC3339),
		})
	}))
	defer upstream.Close()

	cachePath := filepath.Join(t.TempDir(), "approved.json")
	rules := config.RulesConfig{
		MinVersions: config.MinVersionsRule{Enabled: true, Count: 2},
	}
	s := NewServer(rules, cachePath, map[string]string{"go": upstream.URL})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	_ = s

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusBlocked {
		t.Errorf("expected blocked on upstream error, got %s", cr.Status)
	}
}

func TestMatchVersionRange(t *testing.T) {
	tests := []struct {
		version  string
		rangeStr string
		want     bool
	}{
		// Exact match
		{"2.0.7", "= 2.0.7", true},
		{"2.0.6", "= 2.0.7", false},
		// All versions
		{"1.0.0", ">= 0", true},
		{"99.99.99", ">= 0", true},
		// Range
		{"1.5.0", ">= 1.0.0, < 2.0.0", true},
		{"2.0.0", ">= 1.0.0, < 2.0.0", false},
		{"0.9.0", ">= 1.0.0, < 2.0.0", false},
		// Upper bound only
		{"1.0.0", "< 2.0.0", true},
		{"2.0.0", "< 2.0.0", false},
		// Lower bound only
		{"1.0.0", ">= 1.0.0", true},
		{"0.9.0", ">= 1.0.0", false},
	}
	for _, tt := range tests {
		got := matchVersionRange(tt.version, tt.rangeStr)
		if got != tt.want {
			t.Errorf("matchVersionRange(%q, %q) = %v, want %v", tt.version, tt.rangeStr, got, tt.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"2.0.0", "1.99.99", 1},
		{"1.0", "1.0.0", 0},
		{"0", "0.0.0", 0},
	}
	for _, tt := range tests {
		got := compareVersions(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCheckOSVMalware_SkipsWithdrawn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulns":[{"id":"MAL-2026-9999","withdrawn":"2026-04-30T00:00:00Z"}]}`))
	}))
	defer srv.Close()

	id, err := checkOSVMalware(context.Background(), srv.URL, "npm", "evil-pkg", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if id != "" {
		t.Errorf("expected empty (withdrawn), got %q", id)
	}
}

func TestCheckOSVMalware_BlocksActive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulns":[{"id":"MAL-2026-1234"}]}`))
	}))
	defer srv.Close()

	id, err := checkOSVMalware(context.Background(), srv.URL, "npm", "evil-pkg", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if id != "MAL-2026-1234" {
		t.Errorf("expected MAL-2026-1234, got %q", id)
	}
}

func TestCheckOSVMalware_SkipsWithdrawnKeepsActive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulns":[
			{"id":"MAL-2026-RETRACTED","withdrawn":"2026-01-01T00:00:00Z"},
			{"id":"MAL-2026-ACTIVE"}
		]}`))
	}))
	defer srv.Close()

	id, err := checkOSVMalware(context.Background(), srv.URL, "npm", "evil-pkg", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if id != "MAL-2026-ACTIVE" {
		t.Errorf("expected MAL-2026-ACTIVE (skip withdrawn), got %q", id)
	}
}

// TestCheckBlocked_KnownMalware exercises the handleCheck malware check path
// where checkKnownMalware returns a non-empty advisoryID, killing the
// CONDITIONALS_NEGATION mutant on `advisoryID != ""` (server.go:103:98).
func TestCheckBlocked_KnownMalware(t *testing.T) {
	// Mock OSV server that returns an active MAL advisory.
	osvMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulns":[{"id":"MAL-2026-7777"}]}`))
	}))
	defer osvMock.Close()

	// Upstream Go proxy mock (needed for the server to start).
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/@v/list") {
			fmt.Fprintln(w, "v1.0.0")
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"Version": "v1.0.0",
			"Time":    time.Now().AddDate(0, -6, 0).Format(time.RFC3339),
		})
	}))
	defer upstream.Close()

	cachePath := filepath.Join(t.TempDir(), "approved.json")
	rules := config.RulesConfig{
		MaxAge: config.MaxAgeRule{Enabled: true, MinDays: 7},
	}
	s := NewServer(rules, cachePath, map[string]string{"go": upstream.URL})
	s.osvQueryURL = osvMock.URL
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/evil/pkg", Version: "v1.0.0"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusBlocked {
		t.Errorf("expected blocked for known malware, got %s", cr.Status)
	}
	if !strings.Contains(cr.Reason, "MAL-2026-7777") {
		t.Errorf("expected reason to mention advisory ID, got %q", cr.Reason)
	}
}

// TestCheckAllowed_ExactBoundary exercises the age boundary: a package published
// exactly MinDays ago should be allowed because age == maxAge means age < maxAge
// is false. Kills the CONDITIONALS_BOUNDARY mutant on `age < maxAge` (server.go:155:10)
// and the ARITHMETIC_BASE mutant on `age.Hours() / 24` (server.go:156:28).
func TestCheckAllowed_ExactBoundary(t *testing.T) {
	// Package published exactly 7 days ago.
	publishTime := time.Now().Add(-7 * 24 * time.Hour)
	_, srv := newTestServer(t, 7, publishTime)
	defer srv.Close()

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusAllowed {
		t.Errorf("expected allowed when age == maxAge (exact boundary), got %s: %s", cr.Status, cr.Reason)
	}
}

// TestAnalysisEnabled_NoAnalyzers_Passthrough exercises the analysis guard:
// when analysis.Enabled is true but no analyzers are set (len(s.analyzers) == 0),
// the code should skip analysis and allow the package. Kills the
// CONDITIONALS_BOUNDARY mutant on `len(s.analyzers) > 0` (server.go:168:50).
func TestAnalysisEnabled_NoAnalyzers_Passthrough(t *testing.T) {
	rules := config.RulesConfig{
		MaxAge:   config.MaxAgeRule{Enabled: true, MinDays: 7},
		Analysis: config.AnalysisRule{Enabled: true},
	}
	// Package published 6 months ago to pass max_age.
	// Do NOT call SetAnalyzers - analyzers slice stays nil/empty.
	_, srv := newTestServerWithRules(t, rules, time.Now().AddDate(0, -6, 0))
	defer srv.Close()

	body, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusAllowed {
		t.Errorf("expected allowed when analysis enabled but no analyzers, got %s: %s", cr.Status, cr.Reason)
	}
}

// TestCompareVersions_UnequalLengths exercises the boundary conditions in
// compareVersions where bParts has more segments than aParts and vice versa.
// Kills the CONDITIONALS_BOUNDARY mutants on `len(bParts) > maxLen`
// (server.go:426:17) and `i < len(bParts)` (server.go:435:8).
func TestCompareVersions_UnequalLengths(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// bParts longer than aParts, trailing non-zero → a < b
		{"1.0", "1.0.1", -1},
		// aParts longer than bParts, trailing non-zero → a > b
		{"1.0.1", "1.0", 1},
		// bParts longer but trailing zero → equal
		{"1.0", "1.0.0", 0},
		// aParts much longer, trailing zeros → equal
		{"1.0.0.0", "1.0", 0},
		// bParts much longer, small difference in extra segment
		{"2", "2.0.0.1", -1},
	}
	for _, tt := range tests {
		got := compareVersions(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// TestMatchSingleConstraint_BoundaryValues exercises strict and inclusive
// comparison operators at exact boundary values. Kills mutants around
// the comparison result checks in matchSingleConstraint.
func TestMatchSingleConstraint_BoundaryValues(t *testing.T) {
	tests := []struct {
		version    string
		constraint string
		want       bool
	}{
		// "> 1.0.0" with version "1.0.0" → false (equal, not greater)
		{"1.0.0", "> 1.0.0", false},
		// "> 1.0.0" with version "1.0.1" → true
		{"1.0.1", "> 1.0.0", true},
		// "<= 1.0.0" with version "1.0.0" → true (equal is included)
		{"1.0.0", "<= 1.0.0", true},
		// "<= 1.0.0" with version "1.0.1" → false
		{"1.0.1", "<= 1.0.0", false},
		// "<= 1.0.0" with version "0.9.0" → true
		{"0.9.0", "<= 1.0.0", true},
		// "> 1.0.0" with version "0.9.0" → false
		{"0.9.0", "> 1.0.0", false},
	}
	for _, tt := range tests {
		got := matchSingleConstraint(tt.version, tt.constraint)
		if got != tt.want {
			t.Errorf("matchSingleConstraint(%q, %q) = %v, want %v", tt.version, tt.constraint, got, tt.want)
		}
	}
}

// TestCheckKnownMalware_GHSAPath exercises the GHSA malware check path in
// checkKnownMalware when a GitHub token is set. Kills mutants on
// `s.githubToken != ""` (server.go:248:85), `id != ""` (server.go:250:15),
// and `err != nil` (server.go:255:19).
func TestCheckKnownMalware_GHSAPath(t *testing.T) {
	// OSV mock returns no malware (empty vulns).
	osvMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulns":[]}`))
	}))
	defer osvMock.Close()

	// GHSA GraphQL mock returns a MALWARE advisory matching all versions.
	ghsaMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"data": {
				"securityVulnerabilities": {
					"nodes": [{
						"advisory": {"ghsaId": "GHSA-xxxx-yyyy-zzzz"},
						"vulnerableVersionRange": ">= 0"
					}],
					"pageInfo": {"hasNextPage": false, "endCursor": ""}
				}
			}
		}`))
	}))
	defer ghsaMock.Close()

	cachePath := filepath.Join(t.TempDir(), "approved.json")
	rules := config.RulesConfig{}
	s := NewServer(rules, cachePath, map[string]string{"go": "http://unused"})
	s.osvQueryURL = osvMock.URL
	s.ghsaGraphQLURL = ghsaMock.URL
	s.SetGithubToken("fake-token-for-test")

	id, err := s.checkKnownMalware(context.Background(), "go", "github.com/evil/pkg", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("expected GHSA-xxxx-yyyy-zzzz, got %q", id)
	}
}

// TestCheckKnownMalware_GHSASkippedWithoutToken verifies that when no GitHub
// token is set, the GHSA path is skipped and only OSV is consulted.
func TestCheckKnownMalware_GHSASkippedWithoutToken(t *testing.T) {
	// OSV mock returns no malware.
	osvMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulns":[]}`))
	}))
	defer osvMock.Close()

	ghsaCalled := false
	ghsaMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ghsaCalled = true
		w.Write([]byte(`{"data":{"securityVulnerabilities":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}`))
	}))
	defer ghsaMock.Close()

	cachePath := filepath.Join(t.TempDir(), "approved.json")
	rules := config.RulesConfig{}
	s := NewServer(rules, cachePath, map[string]string{"go": "http://unused"})
	s.osvQueryURL = osvMock.URL
	s.ghsaGraphQLURL = ghsaMock.URL
	// Do NOT set github token.

	id, err := s.checkKnownMalware(context.Background(), "go", "github.com/safe/pkg", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "" {
		t.Errorf("expected empty advisory ID, got %q", id)
	}
	if ghsaCalled {
		t.Error("GHSA endpoint should not be called when githubToken is empty")
	}
}
