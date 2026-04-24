//go:build integration

package soa_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ariary/soa/internal/analyzer"
	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/internal/orchestrator"
	"github.com/ariary/soa/internal/provider"
	"github.com/ariary/soa/internal/server"
	"github.com/ariary/soa/pkg/checkapi"
)

func TestEndToEnd_GoGetWithCheckServer(t *testing.T) {
	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
	}))
	defer checkSrv.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/github.com/fake/mod/@v/v1.0.0.info" {
			json.NewEncoder(w).Encode(map[string]any{
				"Version": "v1.0.0",
				"Time":    time.Now().AddDate(0, -1, 0).Format(time.RFC3339),
			})
			return
		}
		if r.URL.Path == "/github.com/fake/mod/@v/v1.0.0.mod" {
			fmt.Fprint(w, "module github.com/fake/mod\n\ngo 1.21\n")
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	cfg := config.Config{
		CheckURL:     checkSrv.URL,
		Proxy:        config.ProxyConfig{Port: 0},
		PollInterval: 50 * time.Millisecond,
		CheckTimeout: 5 * time.Second,
	}

	env := os.Environ()
	env = append(env, "GOPROXY="+upstream.URL)

	managers := []manager.Manager{&manager.GolangManager{}}

	code := orchestrator.Run(cfg, managers, []string{"sh", "-c", "echo $GOPROXY"}, env, false)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
}

func TestEndToEnd_BinaryBuilds(t *testing.T) {
	cmd := exec.Command("go", "build", "-o", "/dev/null", "./cmd/soa/")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build soa: %v\n%s", err, out)
	}
}

func TestEndToEnd_AnalysisPipeline(t *testing.T) {
	// 1. Mock LLM server (Ollama-style)
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"message": map[string]any{
				"role":    "assistant",
				"content": `{"block": false, "summary": "clean", "findings": []}`,
			},
			"prompt_eval_count": 100,
			"eval_count":        50,
		})
	}))
	defer llmSrv.Close()

	// 2. Mock Go proxy upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, ".info"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"Version": "v1.0.0",
				"Time":    time.Now().AddDate(0, -6, 0).Format(time.RFC3339),
			})
		case strings.HasSuffix(path, ".zip"):
			w.Header().Set("Content-Type", "application/zip")
			w.Write(buildTestZip(t))
		case strings.HasSuffix(path, ".mod"):
			fmt.Fprint(w, "module github.com/fake/mod\n\ngo 1.21\n")
		case strings.HasSuffix(path, "list"):
			fmt.Fprint(w, "v1.0.0")
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	// 3. Server setup
	cachePath := filepath.Join(t.TempDir(), "approved.json")
	rules := config.RulesConfig{
		MaxAge:   config.MaxAgeRule{Enabled: true, MinDays: 7},
		Analysis: config.AnalysisRule{Enabled: true, Provider: "ollama", Model: "llama3", MaxSourceBytes: 524288},
	}
	s := server.NewServer(rules, cachePath, map[string]string{"go": upstream.URL})
	llm := provider.NewOllama(llmSrv.URL, "llama3")
	codeAnalyzer := analyzer.NewCodeAnalyzer(llm, map[string]string{"go": upstream.URL}, 524288)
	releaseAnalyzer := analyzer.NewReleaseAnalyzer(llm, "", "", map[string]string{"go": upstream.URL})
	s.SetAnalyzers([]analyzer.Analyzer{codeAnalyzer, releaseAnalyzer})

	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	// 4. POST /check
	reqBody, _ := json.Marshal(checkapi.CheckRequest{Ecosystem: "go", Module: "github.com/fake/mod", Version: "v1.0.0"})
	resp, err := http.Post(ts.URL+"/check", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /check failed: %v", err)
	}
	defer resp.Body.Close()

	var checkResp checkapi.CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&checkResp); err != nil {
		t.Fatalf("failed to decode check response: %v", err)
	}

	if checkResp.Status != checkapi.StatusProcessing {
		t.Fatalf("expected status %q, got %q (reason: %s)", checkapi.StatusProcessing, checkResp.Status, checkResp.Reason)
	}
	if checkResp.ID == "" {
		t.Fatal("expected non-empty job ID")
	}

	// 5. Poll GET /check/{id}
	var finalResp checkapi.CheckResponse
	for i := 0; i < 100; i++ {
		time.Sleep(20 * time.Millisecond)
		pollResp, err := http.Get(ts.URL + "/check/" + checkResp.ID)
		if err != nil {
			t.Fatalf("GET /check/%s failed: %v", checkResp.ID, err)
		}
		if err := json.NewDecoder(pollResp.Body).Decode(&finalResp); err != nil {
			pollResp.Body.Close()
			t.Fatalf("failed to decode poll response: %v", err)
		}
		pollResp.Body.Close()

		if finalResp.Status != checkapi.StatusProcessing {
			break
		}
	}

	if finalResp.Status != checkapi.StatusAllowed {
		t.Errorf("expected final status %q, got %q (reason: %s)", checkapi.StatusAllowed, finalResp.Status, finalResp.Reason)
	}
}

// buildTestZip creates a minimal valid zip archive containing one clean Go file.
func buildTestZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("github.com/fake/mod@v1.0.0/main.go")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	fmt.Fprint(f, "package main\n\nfunc main() {}\n")
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}
