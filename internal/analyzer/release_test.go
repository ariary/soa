package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReleaseAnalyzer_Clean(t *testing.T) {
	// Mock GitHub server.
	ghMux := http.NewServeMux()
	ghMux.HandleFunc("/repos/example/repo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"owner":            map[string]string{"login": "example"},
			"stargazers_count": 5000,
			"forks_count":      300,
			"created_at":       "2019-03-10T00:00:00Z",
		})
	})
	ghMux.HandleFunc("/repos/example/repo/contributors", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"login": "maintainer", "contributions": 200},
		})
	})
	ghMux.HandleFunc("/users/maintainer", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"created_at":   "2015-01-01T00:00:00Z",
			"public_repos": 50,
		})
	})
	ghMux.HandleFunc("/repos/example/repo/compare/v1.0.0...v1.0.1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_commits": 2,
			"files": []map[string]interface{}{
				{"filename": "lib.go", "additions": 3, "deletions": 1},
			},
		})
	})
	ghSrv := httptest.NewServer(ghMux)
	defer ghSrv.Close()

	// Mock Go module proxy.
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/github.com/example/repo/@v/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("v1.0.0\nv1.0.1\n"))
	})
	proxyMux.HandleFunc("/github.com/example/repo/@v/v1.0.1.info", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Version": "v1.0.1",
			"Time":    "2024-06-01T12:00:00Z",
		})
	})
	proxyMux.HandleFunc("/github.com/example/repo/@v/v1.0.1.mod", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("module github.com/example/repo\n\ngo 1.21\n"))
	})
	proxyMux.HandleFunc("/github.com/example/repo/@v/v1.0.0.mod", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("module github.com/example/repo\n\ngo 1.21\n"))
	})
	proxySrv := httptest.NewServer(proxyMux)
	defer proxySrv.Close()

	mock := &mockProvider{
		response: `{"block":false,"summary":"No suspicious release signals detected.","findings":[]}`,
	}

	ra := NewReleaseAnalyzer(mock, ghSrv.URL, "gh-token", proxySrv.URL)
	result, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "go",
		Module:  "github.com/example/repo",
		Version: "v1.0.1",
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
}

func TestReleaseAnalyzer_NoGitHub(t *testing.T) {
	// Mock Go module proxy for a non-GitHub module.
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/example.com/mod/@v/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("v0.1.0\nv0.2.0\n"))
	})
	proxyMux.HandleFunc("/example.com/mod/@v/v0.2.0.info", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Version": "v0.2.0",
			"Time":    "2024-07-01T10:00:00Z",
		})
	})
	proxyMux.HandleFunc("/example.com/mod/@v/v0.2.0.mod", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("module example.com/mod\n\ngo 1.22\n"))
	})
	proxyMux.HandleFunc("/example.com/mod/@v/v0.1.0.mod", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("module example.com/mod\n\ngo 1.21\n"))
	})
	proxySrv := httptest.NewServer(proxyMux)
	defer proxySrv.Close()

	mock := &mockProvider{
		response: `{"block":false,"summary":"No suspicious release signals detected.","findings":[]}`,
	}

	// No GitHub base URL or token — gh client should be nil.
	ra := NewReleaseAnalyzer(mock, "", "", proxySrv.URL)
	result, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "go",
		Module:  "example.com/mod",
		Version: "v0.2.0",
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
}

func TestParseGitHubPath(t *testing.T) {
	tests := []struct {
		module     string
		wantOwner  string
		wantRepo   string
	}{
		{"github.com/ariary/soa", "ariary", "soa"},
		{"github.com/golang/go", "golang", "go"},
		{"github.com/user/repo/v2", "user", "repo"},
		{"example.com/mod", "", ""},
		{"github.com/nopath", "", ""},
	}
	for _, tt := range tests {
		owner, repo := parseGitHubPath(tt.module)
		if owner != tt.wantOwner || repo != tt.wantRepo {
			t.Errorf("parseGitHubPath(%q) = (%q, %q), want (%q, %q)",
				tt.module, owner, repo, tt.wantOwner, tt.wantRepo)
		}
	}
}

func TestGuessPreviousTag(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"v1.0.1", "v1.0.0"},
		{"v2.3.5", "v2.3.4"},
		{"v1.0.0", ""},
		{"v1.0", ""},
		{"notaversion", ""},
	}
	for _, tt := range tests {
		got := guessPreviousTag(tt.version)
		if got != tt.want {
			t.Errorf("guessPreviousTag(%q) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

func TestFindPreviousVersion(t *testing.T) {
	versions := []string{"v1.0.0", "v1.0.1", "v1.1.0"}

	tests := []struct {
		current string
		want    string
	}{
		{"v1.0.1", "v1.0.0"},
		{"v1.1.0", "v1.0.1"},
		{"v1.0.0", ""},
		{"v2.0.0", ""},
	}
	for _, tt := range tests {
		got := findPreviousVersion(versions, tt.current)
		if got != tt.want {
			t.Errorf("findPreviousVersion(%v, %q) = %q, want %q",
				versions, tt.current, got, tt.want)
		}
	}
}
