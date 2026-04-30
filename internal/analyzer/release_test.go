package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

	ra := NewReleaseAnalyzer(mock, ghSrv.URL, "gh-token", map[string]string{"go": proxySrv.URL})
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
	ra := NewReleaseAnalyzer(mock, "", "", map[string]string{"go": proxySrv.URL})
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

// TestNewReleaseAnalyzer_GitHubClient verifies that the GitHub client is created
// only when at least one of githubBaseURL or githubToken is non-empty.
// Kills mutants:
//   - release.go:32:39  ARITHMETIC_BASE (30 * time.Second timeout)
//   - release.go:34:19,34:40 CONDITIONALS_NEGATION (githubBaseURL != "" || githubToken != "")
func TestNewReleaseAnalyzer_GitHubClient(t *testing.T) {
	mock := &mockProvider{response: "{}"}

	// Both empty -> gh must be nil
	ra := NewReleaseAnalyzer(mock, "", "", nil)
	if ra.gh != nil {
		t.Error("expected gh == nil when both baseURL and token are empty")
	}
	if ra.client == nil {
		t.Fatal("expected non-nil http client")
	}
	if ra.client.Timeout != 30*time.Second {
		t.Errorf("expected client timeout 30s, got %v", ra.client.Timeout)
	}

	// Only baseURL set -> gh must be non-nil
	ra = NewReleaseAnalyzer(mock, "https://api.github.com", "", nil)
	if ra.gh == nil {
		t.Error("expected gh != nil when baseURL is set")
	}

	// Only token set -> gh must be non-nil
	ra = NewReleaseAnalyzer(mock, "", "tok", nil)
	if ra.gh == nil {
		t.Error("expected gh != nil when token is set")
	}

	// Both set -> gh must be non-nil
	ra = NewReleaseAnalyzer(mock, "https://api.github.com", "tok", nil)
	if ra.gh == nil {
		t.Error("expected gh != nil when both baseURL and token are set")
	}
}

// TestGuessPreviousTag_Boundaries targets the boundary condition
// lastChar < '1' || lastChar > '9' at release.go:561:32.
func TestGuessPreviousTag_Boundaries(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		// '1' is the boundary: lastChar < '1' is false, so it passes through
		{"v1.0.1", "v1.0.0"},
		// '9' is the upper boundary: lastChar > '9' is false, so it passes through
		{"v1.0.9", "v1.0.8"},
		// '0' is handled by the patch == "0" check, returns ""
		{"v1.0.0", ""},
		// patch ending with a non-digit character
		{"v1.0.1a", ""},
		// patch ending with '0' but multi-digit patch (not == "0"), and lastChar < '1'
		{"v1.0.10", ""},
		// multi-digit patch ending in digit > 0
		{"v1.0.12", "v1.0.11"},
		// empty patch component
		{"v1.0.", ""},
		// no v prefix
		{"1.0.1", ""},
		// too few parts
		{"v1.0", ""},
		// too many parts
		{"v1.0.1.2", ""},
	}
	for _, tt := range tests {
		got := guessPreviousTag(tt.version)
		if got != tt.want {
			t.Errorf("guessPreviousTag(%q) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

// TestParseGenericGitHubURL tests various URL formats including edge cases.
func TestParseGenericGitHubURL(t *testing.T) {
	tests := []struct {
		rawURL    string
		wantOwner string
		wantRepo  string
	}{
		// Standard HTTPS
		{"https://github.com/owner/repo", "owner", "repo"},
		// With .git suffix
		{"https://github.com/owner/repo.git", "owner", "repo"},
		// git+ prefix
		{"git+https://github.com/owner/repo.git", "owner", "repo"},
		// git:// protocol
		{"git://github.com/owner/repo", "owner", "repo"},
		// http
		{"http://github.com/owner/repo", "owner", "repo"},
		// Trailing slash
		{"https://github.com/owner/repo/", "owner", "repo"},
		// Extra path segments
		{"https://github.com/owner/repo/tree/main", "owner", "repo"},
		// Not GitHub
		{"https://gitlab.com/owner/repo", "", ""},
		// Empty string
		{"", "", ""},
		// Only one path component
		{"https://github.com/owner", "", ""},
		// Empty owner
		{"https://github.com//repo", "", ""},
		// Empty repo
		{"https://github.com/owner/", "", ""},
		// Just github.com
		{"github.com/owner/repo", "owner", "repo"},
	}
	for _, tt := range tests {
		owner, repo := parseGenericGitHubURL(tt.rawURL)
		if owner != tt.wantOwner || repo != tt.wantRepo {
			t.Errorf("parseGenericGitHubURL(%q) = (%q, %q), want (%q, %q)",
				tt.rawURL, owner, repo, tt.wantOwner, tt.wantRepo)
		}
	}
}

// TestCollectGoMetadata_PartialErrors verifies that Go metadata collection
// gracefully handles individual endpoint errors while continuing to collect
// other data. Kills mutants in release.go:98-136.
func TestCollectGoMetadata_PartialErrors(t *testing.T) {
	// Proxy that returns errors for version info and current go.mod,
	// but succeeds for version list and previous go.mod.
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/mod/@v/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("v1.0.0\nv1.0.1\n"))
	})
	proxyMux.HandleFunc("/mod/@v/v1.0.1.info", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	proxyMux.HandleFunc("/mod/@v/v1.0.1.mod", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	})
	proxyMux.HandleFunc("/mod/@v/v1.0.0.mod", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("module mod\n\ngo 1.21\n"))
	})
	proxySrv := httptest.NewServer(proxyMux)
	defer proxySrv.Close()

	mock := &mockProvider{
		response: `{"block":false,"summary":"ok","findings":[]}`,
	}
	ra := NewReleaseAnalyzer(mock, "", "", map[string]string{"go": proxySrv.URL})
	result, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "go",
		Module:    "mod",
		Version:   "v1.0.1",
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if result.Block {
		t.Error("expected Block=false")
	}
}

// TestCollectGoMetadata_VersionListError verifies behavior when the version
// list endpoint fails. Kills mutant at release.go:98.
func TestCollectGoMetadata_VersionListError(t *testing.T) {
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/mod/@v/list", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	})
	proxyMux.HandleFunc("/mod/@v/v1.0.1.info", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Version": "v1.0.1",
			"Time":    "2024-06-01T12:00:00Z",
		})
	})
	proxyMux.HandleFunc("/mod/@v/v1.0.1.mod", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("module mod\n\ngo 1.21\n"))
	})
	proxySrv := httptest.NewServer(proxyMux)
	defer proxySrv.Close()

	mock := &mockProvider{
		response: `{"block":false,"summary":"ok","findings":[]}`,
	}
	// version list fails -> prevVersion falls back to guessPreviousTag
	ra := NewReleaseAnalyzer(mock, "", "", map[string]string{"go": proxySrv.URL})
	result, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "go",
		Module:    "mod",
		Version:   "v1.0.1",
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if result.Block {
		t.Error("expected Block=false")
	}
}

// TestCollectGoMetadata_NoUpstream verifies error when no go upstream is set.
func TestCollectGoMetadata_NoUpstream(t *testing.T) {
	mock := &mockProvider{
		response: `{"block":false,"summary":"ok","findings":[]}`,
	}
	ra := NewReleaseAnalyzer(mock, "", "", map[string]string{})
	_, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "go",
		Module:    "mod",
		Version:   "v1.0.1",
	})
	if err == nil {
		t.Fatal("expected error when no go upstream configured")
	}
	if !strings.Contains(err.Error(), "no upstream configured") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAppendGitHubData_Guards verifies that appendGitHubData returns early
// when gh is nil, owner is empty, or repo is empty.
// Kills mutant at release.go:394:11,394:27,394:41 CONDITIONALS_NEGATION.
func TestAppendGitHubData_Guards(t *testing.T) {
	ghMux := http.NewServeMux()
	ghMux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"owner":            map[string]string{"login": "owner"},
			"stargazers_count": 10,
			"forks_count":      1,
			"created_at":       "2020-01-01T00:00:00Z",
		})
	})
	ghMux.HandleFunc("/repos/owner/repo/contributors", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	ghSrv := httptest.NewServer(ghMux)
	defer ghSrv.Close()

	mock := &mockProvider{response: "{}"}
	ctx := context.Background()

	// Case 1: gh is nil -> no GitHub data appended
	raNilGH := NewReleaseAnalyzer(mock, "", "", nil)
	var sb1 strings.Builder
	raNilGH.appendGitHubData(ctx, &sb1, "owner", "repo", "", "v1.0.0")
	if sb1.Len() != 0 {
		t.Errorf("expected empty output when gh is nil, got %q", sb1.String())
	}

	// Case 2: owner is empty -> no GitHub data appended
	raWithGH := NewReleaseAnalyzer(mock, ghSrv.URL, "tok", nil)
	var sb2 strings.Builder
	raWithGH.appendGitHubData(ctx, &sb2, "", "repo", "", "v1.0.0")
	if sb2.Len() != 0 {
		t.Errorf("expected empty output when owner is empty, got %q", sb2.String())
	}

	// Case 3: repo is empty -> no GitHub data appended
	var sb3 strings.Builder
	raWithGH.appendGitHubData(ctx, &sb3, "owner", "", "", "v1.0.0")
	if sb3.Len() != 0 {
		t.Errorf("expected empty output when repo is empty, got %q", sb3.String())
	}

	// Case 4: all set -> should produce output
	var sb4 strings.Builder
	raWithGH.appendGitHubData(ctx, &sb4, "owner", "repo", "", "v1.0.0")
	if !strings.Contains(sb4.String(), "## GitHub Data") {
		t.Errorf("expected GitHub data output when all params set, got %q", sb4.String())
	}
}

// TestAppendGitHubData_WithPrevVersion verifies that compare data is fetched
// when a previous version is provided. Kills mutants at release.go:415,417.
func TestAppendGitHubData_WithPrevVersion(t *testing.T) {
	ghMux := http.NewServeMux()
	ghMux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"owner":            map[string]string{"login": "owner"},
			"stargazers_count": 10,
			"forks_count":      1,
			"created_at":       "2020-01-01T00:00:00Z",
		})
	})
	ghMux.HandleFunc("/repos/owner/repo/contributors", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"login": "dev1", "contributions": 50},
		})
	})
	ghMux.HandleFunc("/users/dev1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"created_at":   "2018-01-01T00:00:00Z",
			"public_repos": 20,
		})
	})
	ghMux.HandleFunc("/repos/owner/repo/compare/v1.0.0...v1.0.1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_commits": 3,
			"files": []map[string]interface{}{
				{"filename": "main.go", "additions": 10, "deletions": 2},
			},
		})
	})
	ghSrv := httptest.NewServer(ghMux)
	defer ghSrv.Close()

	mock := &mockProvider{response: "{}"}
	ra := NewReleaseAnalyzer(mock, ghSrv.URL, "tok", nil)

	var sb strings.Builder
	ra.appendGitHubData(context.Background(), &sb, "owner", "repo", "v1.0.0", "v1.0.1")
	out := sb.String()

	if !strings.Contains(out, "## GitHub Data") {
		t.Error("expected GitHub Data header")
	}
	if !strings.Contains(out, "Compare v1.0.0...v1.0.1") {
		t.Error("expected compare section")
	}
	if !strings.Contains(out, "Total commits: 3") {
		t.Error("expected total commits")
	}
	if !strings.Contains(out, "main.go") {
		t.Error("expected file change")
	}
	if !strings.Contains(out, "dev1") {
		t.Error("expected contributor info")
	}
}

// TestAppendGitHubData_RepoInfoError verifies graceful handling when
// the repo info endpoint fails. Kills mutants at release.go:400.
func TestAppendGitHubData_RepoInfoError(t *testing.T) {
	ghMux := http.NewServeMux()
	ghMux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	ghMux.HandleFunc("/repos/owner/repo/contributors", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	ghSrv := httptest.NewServer(ghMux)
	defer ghSrv.Close()

	mock := &mockProvider{response: "{}"}
	ra := NewReleaseAnalyzer(mock, ghSrv.URL, "tok", nil)

	var sb strings.Builder
	ra.appendGitHubData(context.Background(), &sb, "owner", "repo", "", "v1.0.0")
	out := sb.String()

	// Should still have the header but no Repository section
	if !strings.Contains(out, "## GitHub Data") {
		t.Error("expected GitHub Data header even when repo info fails")
	}
	if strings.Contains(out, "### Repository") {
		t.Error("did not expect Repository section when repo info endpoint fails")
	}
}

// TestAppendGitHubData_ContributorsEmpty verifies behavior when contributors
// endpoint returns empty list. Kills mutant at release.go:406:33.
func TestAppendGitHubData_ContributorsEmpty(t *testing.T) {
	ghMux := http.NewServeMux()
	ghMux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"owner":            map[string]string{"login": "owner"},
			"stargazers_count": 10,
			"forks_count":      1,
			"created_at":       "2020-01-01T00:00:00Z",
		})
	})
	ghMux.HandleFunc("/repos/owner/repo/contributors", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	ghSrv := httptest.NewServer(ghMux)
	defer ghSrv.Close()

	mock := &mockProvider{response: "{}"}
	ra := NewReleaseAnalyzer(mock, ghSrv.URL, "tok", nil)

	var sb strings.Builder
	ra.appendGitHubData(context.Background(), &sb, "owner", "repo", "", "v1.0.0")
	out := sb.String()

	if !strings.Contains(out, "### Repository") {
		t.Error("expected Repository section")
	}
	if strings.Contains(out, "### Contributors") {
		t.Error("did not expect Contributors section for empty list")
	}
}

// TestAppendGitHubData_CompareError verifies behavior when the compare
// endpoint fails. Kills mutant at release.go:417.
func TestAppendGitHubData_CompareError(t *testing.T) {
	ghMux := http.NewServeMux()
	ghMux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"owner":            map[string]string{"login": "owner"},
			"stargazers_count": 10,
			"forks_count":      1,
			"created_at":       "2020-01-01T00:00:00Z",
		})
	})
	ghMux.HandleFunc("/repos/owner/repo/contributors", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	ghMux.HandleFunc("/repos/owner/repo/compare/v1.0.0...v1.0.1", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	})
	ghSrv := httptest.NewServer(ghMux)
	defer ghSrv.Close()

	mock := &mockProvider{response: "{}"}
	ra := NewReleaseAnalyzer(mock, ghSrv.URL, "tok", nil)

	var sb strings.Builder
	ra.appendGitHubData(context.Background(), &sb, "owner", "repo", "v1.0.0", "v1.0.1")
	out := sb.String()

	if !strings.Contains(out, "## GitHub Data") {
		t.Error("expected GitHub Data header")
	}
	if strings.Contains(out, "Compare") {
		t.Error("did not expect Compare section when compare endpoint fails")
	}
}

// TestReleaseAnalyzer_NpmMetadata tests the npm ecosystem metadata path.
// Kills mutants in the npm-specific code path.
func TestReleaseAnalyzer_NpmMetadata(t *testing.T) {
	npmMux := http.NewServeMux()
	npmMux.HandleFunc("/my-pkg", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name": "my-pkg",
			"time": map[string]string{
				"1.0.0":    "2024-01-01T00:00:00Z",
				"1.0.1":    "2024-06-01T00:00:00Z",
				"created":  "2024-01-01T00:00:00Z",
				"modified": "2024-06-01T00:00:00Z",
			},
			"maintainers": []map[string]string{
				{"name": "alice", "email": "alice@example.com"},
			},
			"versions": map[string]interface{}{
				"1.0.0": map[string]interface{}{
					"dependencies": map[string]string{"lodash": "^4.0.0"},
				},
				"1.0.1": map[string]interface{}{
					"dependencies":    map[string]string{"lodash": "^4.1.0", "axios": "^1.0.0"},
					"devDependencies": map[string]string{"jest": "^29.0.0"},
				},
			},
			"repository": map[string]string{
				"url": "git+https://github.com/npmowner/npmrepo.git",
			},
		})
	})
	npmSrv := httptest.NewServer(npmMux)
	defer npmSrv.Close()

	ghMux := http.NewServeMux()
	ghMux.HandleFunc("/repos/npmowner/npmrepo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"owner":            map[string]string{"login": "npmowner"},
			"stargazers_count": 100,
			"forks_count":      10,
			"created_at":       "2020-01-01T00:00:00Z",
		})
	})
	ghMux.HandleFunc("/repos/npmowner/npmrepo/contributors", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	ghSrv := httptest.NewServer(ghMux)
	defer ghSrv.Close()

	mock := &mockProvider{
		response: `{"block":false,"summary":"ok","findings":[]}`,
	}
	ra := NewReleaseAnalyzer(mock, ghSrv.URL, "tok", map[string]string{"npm": npmSrv.URL})
	result, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "npm",
		Module:    "my-pkg",
		Version:   "1.0.1",
	})
	if err != nil {
		t.Fatalf("Analyze npm: %v", err)
	}
	if result.Block {
		t.Error("expected Block=false")
	}
}

// TestReleaseAnalyzer_NpmMetadata_NoUpstream verifies npm errors without upstream.
func TestReleaseAnalyzer_NpmMetadata_NoUpstream(t *testing.T) {
	mock := &mockProvider{response: `{"block":false,"summary":"ok","findings":[]}`}
	ra := NewReleaseAnalyzer(mock, "", "", map[string]string{})
	_, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "npm",
		Module:    "my-pkg",
		Version:   "1.0.0",
	})
	if err == nil {
		t.Fatal("expected error when no npm upstream configured")
	}
	if !strings.Contains(err.Error(), "no upstream configured for npm") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestReleaseAnalyzer_PipMetadata tests the pip/PyPI ecosystem metadata path.
func TestReleaseAnalyzer_PipMetadata(t *testing.T) {
	pipMux := http.NewServeMux()
	pipMux.HandleFunc("/pypi/mypackage/json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"info": map[string]interface{}{
				"name":         "mypackage",
				"author":       "Bob",
				"author_email": "bob@example.com",
				"requires_dist": []string{"requests>=2.0", "click>=7.0"},
				"project_urls": map[string]string{
					"Source": "https://github.com/pipowner/piprepo",
				},
			},
			"releases": map[string]interface{}{
				"1.0.0": []map[string]string{
					{"upload_time_iso_8601": "2024-01-01T00:00:00Z"},
				},
				"1.0.1": []map[string]string{
					{"upload_time_iso_8601": "2024-06-01T00:00:00Z"},
				},
			},
		})
	})
	pipSrv := httptest.NewServer(pipMux)
	defer pipSrv.Close()

	ghMux := http.NewServeMux()
	ghMux.HandleFunc("/repos/pipowner/piprepo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"owner":            map[string]string{"login": "pipowner"},
			"stargazers_count": 50,
			"forks_count":      5,
			"created_at":       "2021-01-01T00:00:00Z",
		})
	})
	ghMux.HandleFunc("/repos/pipowner/piprepo/contributors", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	ghSrv := httptest.NewServer(ghMux)
	defer ghSrv.Close()

	mock := &mockProvider{
		response: `{"block":false,"summary":"ok","findings":[]}`,
	}
	ra := NewReleaseAnalyzer(mock, ghSrv.URL, "tok", map[string]string{"pip": pipSrv.URL})
	result, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "pip",
		Module:    "mypackage",
		Version:   "1.0.1",
	})
	if err != nil {
		t.Fatalf("Analyze pip: %v", err)
	}
	if result.Block {
		t.Error("expected Block=false")
	}
}

// TestReleaseAnalyzer_PipMetadata_NoUpstream verifies pip errors without upstream.
func TestReleaseAnalyzer_PipMetadata_NoUpstream(t *testing.T) {
	mock := &mockProvider{response: `{"block":false,"summary":"ok","findings":[]}`}
	ra := NewReleaseAnalyzer(mock, "", "", map[string]string{})
	_, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "pip",
		Module:    "mypackage",
		Version:   "1.0.0",
	})
	if err == nil {
		t.Fatal("expected error when no pip upstream configured")
	}
	if !strings.Contains(err.Error(), "no upstream configured for pip") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestReleaseAnalyzer_RubyGemsMetadata tests the rubygems ecosystem metadata path.
func TestReleaseAnalyzer_RubyGemsMetadata(t *testing.T) {
	gemMux := http.NewServeMux()
	gemMux.HandleFunc("/api/v1/versions/mygem.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"number": "1.0.0", "created_at": "2024-01-01T00:00:00Z", "authors": "Charlie"},
			{"number": "1.0.1", "created_at": "2024-06-01T00:00:00Z", "authors": "Charlie"},
		})
	})
	gemMux.HandleFunc("/api/v2/rubygems/mygem/versions/1.0.1.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authors":         "Charlie",
			"description":     "A test gem",
			"source_code_uri": "https://github.com/gemowner/gemrepo",
			"dependencies": map[string]interface{}{
				"runtime": []map[string]interface{}{
					{"name": "rake", "requirements": ">= 12.0"},
				},
			},
		})
	})
	gemSrv := httptest.NewServer(gemMux)
	defer gemSrv.Close()

	ghMux := http.NewServeMux()
	ghMux.HandleFunc("/repos/gemowner/gemrepo", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"owner":            map[string]string{"login": "gemowner"},
			"stargazers_count": 30,
			"forks_count":      3,
			"created_at":       "2022-01-01T00:00:00Z",
		})
	})
	ghMux.HandleFunc("/repos/gemowner/gemrepo/contributors", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	ghSrv := httptest.NewServer(ghMux)
	defer ghSrv.Close()

	mock := &mockProvider{
		response: `{"block":false,"summary":"ok","findings":[]}`,
	}
	ra := NewReleaseAnalyzer(mock, ghSrv.URL, "tok", map[string]string{"rubygems": gemSrv.URL})
	result, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "rubygems",
		Module:    "mygem",
		Version:   "1.0.1",
	})
	if err != nil {
		t.Fatalf("Analyze rubygems: %v", err)
	}
	if result.Block {
		t.Error("expected Block=false")
	}
}

// TestReleaseAnalyzer_RubyGemsMetadata_NoUpstream verifies rubygems errors without upstream.
func TestReleaseAnalyzer_RubyGemsMetadata_NoUpstream(t *testing.T) {
	mock := &mockProvider{response: `{"block":false,"summary":"ok","findings":[]}`}
	ra := NewReleaseAnalyzer(mock, "", "", map[string]string{})
	_, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "rubygems",
		Module:    "mygem",
		Version:   "1.0.0",
	})
	if err == nil {
		t.Fatal("expected error when no rubygems upstream configured")
	}
	if !strings.Contains(err.Error(), "no upstream configured for rubygems") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestReleaseAnalyzer_RubyGemsMetadata_VersionsError tests graceful handling
// when the versions endpoint fails.
func TestReleaseAnalyzer_RubyGemsMetadata_VersionsError(t *testing.T) {
	gemMux := http.NewServeMux()
	gemMux.HandleFunc("/api/v1/versions/mygem.json", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	})
	gemMux.HandleFunc("/api/v2/rubygems/mygem/versions/1.0.1.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authors":         "Charlie",
			"description":     "A test gem",
			"source_code_uri": "",
		})
	})
	gemSrv := httptest.NewServer(gemMux)
	defer gemSrv.Close()

	mock := &mockProvider{
		response: `{"block":false,"summary":"ok","findings":[]}`,
	}
	ra := NewReleaseAnalyzer(mock, "", "", map[string]string{"rubygems": gemSrv.URL})
	result, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "rubygems",
		Module:    "mygem",
		Version:   "1.0.1",
	})
	if err != nil {
		t.Fatalf("Analyze rubygems: %v", err)
	}
	if result.Block {
		t.Error("expected Block=false")
	}
}

// TestFetchGoVersionList_EmptyBody verifies that an empty version list
// returns nil without error. Kills mutant at release.go:474.
func TestFetchGoVersionList_EmptyBody(t *testing.T) {
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/mod/@v/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(""))
	})
	proxySrv := httptest.NewServer(proxyMux)
	defer proxySrv.Close()

	ra := &ReleaseAnalyzer{
		client: &http.Client{Timeout: 5 * time.Second},
	}
	versions, err := ra.fetchGoVersionList(context.Background(), proxySrv.URL, "mod")
	if err != nil {
		t.Fatalf("fetchGoVersionList: %v", err)
	}
	if versions != nil {
		t.Errorf("expected nil versions for empty body, got %v", versions)
	}
}

// TestFetchGoVersionList_WhitespaceOnly verifies that whitespace-only response
// also returns nil.
func TestFetchGoVersionList_WhitespaceOnly(t *testing.T) {
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/mod/@v/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("   \n  \n  "))
	})
	proxySrv := httptest.NewServer(proxyMux)
	defer proxySrv.Close()

	ra := &ReleaseAnalyzer{
		client: &http.Client{Timeout: 5 * time.Second},
	}
	versions, err := ra.fetchGoVersionList(context.Background(), proxySrv.URL, "mod")
	if err != nil {
		t.Fatalf("fetchGoVersionList: %v", err)
	}
	if versions != nil {
		t.Errorf("expected nil versions for whitespace-only body, got %v", versions)
	}
}

// TestFetchGoVersionList_HTTPError verifies error handling when the endpoint
// returns a non-200 status. Kills mutant at release.go:470.
func TestFetchGoVersionList_HTTPError(t *testing.T) {
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/mod/@v/list", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	})
	proxySrv := httptest.NewServer(proxyMux)
	defer proxySrv.Close()

	ra := &ReleaseAnalyzer{
		client: &http.Client{Timeout: 5 * time.Second},
	}
	_, err := ra.fetchGoVersionList(context.Background(), proxySrv.URL, "mod")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

// TestFetchGoVersionInfo_InvalidJSON verifies that unparseable JSON is returned
// as raw body without error. Kills mutant at release.go:493.
func TestFetchGoVersionInfo_InvalidJSON(t *testing.T) {
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/mod/@v/v1.0.0.info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not json"))
	})
	proxySrv := httptest.NewServer(proxyMux)
	defer proxySrv.Close()

	ra := &ReleaseAnalyzer{
		client: &http.Client{Timeout: 5 * time.Second},
	}
	info, err := ra.fetchGoVersionInfo(context.Background(), proxySrv.URL, "mod", "v1.0.0")
	if err != nil {
		t.Fatalf("fetchGoVersionInfo: %v", err)
	}
	if info != "this is not json" {
		t.Errorf("expected raw body returned, got %q", info)
	}
}

// TestFetchGoVersionInfo_ValidJSON verifies proper parsing of valid JSON.
func TestFetchGoVersionInfo_ValidJSON(t *testing.T) {
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/mod/@v/v1.0.0.info", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Version": "v1.0.0",
			"Time":    "2024-06-01T12:00:00Z",
		})
	})
	proxySrv := httptest.NewServer(proxyMux)
	defer proxySrv.Close()

	ra := &ReleaseAnalyzer{
		client: &http.Client{Timeout: 5 * time.Second},
	}
	info, err := ra.fetchGoVersionInfo(context.Background(), proxySrv.URL, "mod", "v1.0.0")
	if err != nil {
		t.Fatalf("fetchGoVersionInfo: %v", err)
	}
	if !strings.Contains(info, "v1.0.0") {
		t.Errorf("expected version in output, got %q", info)
	}
	if !strings.Contains(info, "2024-06-01") {
		t.Errorf("expected date in output, got %q", info)
	}
}

// TestFetchGoVersionInfo_HTTPError verifies error propagation when
// the .info endpoint fails. Kills mutant at release.go:485.
func TestFetchGoVersionInfo_HTTPError(t *testing.T) {
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/mod/@v/v1.0.0.info", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	proxySrv := httptest.NewServer(proxyMux)
	defer proxySrv.Close()

	ra := &ReleaseAnalyzer{
		client: &http.Client{Timeout: 5 * time.Second},
	}
	_, err := ra.fetchGoVersionInfo(context.Background(), proxySrv.URL, "mod", "v1.0.0")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

// TestFetchGoMod_HTTPError verifies error handling when go.mod fetch fails.
// Kills mutant at release.go:508.
func TestFetchGoMod_HTTPError(t *testing.T) {
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/mod/@v/v1.0.0.mod", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	})
	proxySrv := httptest.NewServer(proxyMux)
	defer proxySrv.Close()

	ra := &ReleaseAnalyzer{
		client: &http.Client{Timeout: 5 * time.Second},
	}
	_, err := ra.fetchGoMod(context.Background(), proxySrv.URL, "mod", "v1.0.0")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

// TestHttpGet_NonOKStatus verifies that httpGet returns an error for non-200
// status codes. Kills mutant at release.go:518.
func TestHttpGet_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	ra := &ReleaseAnalyzer{
		client: &http.Client{Timeout: 5 * time.Second},
	}
	_, err := ra.httpGet(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403 in error, got: %v", err)
	}
}

// TestHttpGet_InvalidURL verifies httpGet returns error for invalid URL.
// Kills mutant at release.go:508.
func TestHttpGet_InvalidURL(t *testing.T) {
	ra := &ReleaseAnalyzer{
		client: &http.Client{Timeout: 5 * time.Second},
	}
	_, err := ra.httpGet(context.Background(), "http://localhost:0/nonexistent")
	if err == nil {
		t.Fatal("expected error for connection failure")
	}
}

// TestHttpGet_Success verifies happy path.
func TestHttpGet_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer srv.Close()

	ra := &ReleaseAnalyzer{
		client: &http.Client{Timeout: 5 * time.Second},
	}
	body, err := ra.httpGet(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("httpGet: %v", err)
	}
	if body != "hello" {
		t.Errorf("expected 'hello', got %q", body)
	}
}

// TestParsePipGitHubURL tests the pip-specific GitHub URL parser.
func TestParsePipGitHubURL(t *testing.T) {
	tests := []struct {
		name      string
		urls      map[string]string
		wantOwner string
		wantRepo  string
	}{
		{
			name:      "source url",
			urls:      map[string]string{"Source": "https://github.com/owner/repo"},
			wantOwner: "owner",
			wantRepo:  "repo",
		},
		{
			name:      "no github url",
			urls:      map[string]string{"Homepage": "https://example.com"},
			wantOwner: "",
			wantRepo:  "",
		},
		{
			name:      "empty map",
			urls:      map[string]string{},
			wantOwner: "",
			wantRepo:  "",
		},
		{
			name:      "nil map",
			urls:      nil,
			wantOwner: "",
			wantRepo:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo := parsePipGitHubURL(tt.urls)
			if owner != tt.wantOwner || repo != tt.wantRepo {
				t.Errorf("parsePipGitHubURL(%v) = (%q, %q), want (%q, %q)",
					tt.urls, owner, repo, tt.wantOwner, tt.wantRepo)
			}
		})
	}
}

// TestParseNpmGitHubURL tests the npm-specific GitHub URL parser.
func TestParseNpmGitHubURL(t *testing.T) {
	tests := []struct {
		url       string
		wantOwner string
		wantRepo  string
	}{
		{"git+https://github.com/owner/repo.git", "owner", "repo"},
		{"https://github.com/owner/repo", "owner", "repo"},
		{"", "", ""},
		{"https://gitlab.com/owner/repo", "", ""},
	}
	for _, tt := range tests {
		owner, repo := parseNpmGitHubURL(tt.url)
		if owner != tt.wantOwner || repo != tt.wantRepo {
			t.Errorf("parseNpmGitHubURL(%q) = (%q, %q), want (%q, %q)",
				tt.url, owner, repo, tt.wantOwner, tt.wantRepo)
		}
	}
}

// TestCollectGoMetadata_VerifyContent uses a capturing mock to verify that
// the metadata string sent to the LLM contains expected content from each
// successful fetch. Kills remaining CONDITIONALS_NEGATION mutants in
// collectGoMetadata (lines 98-136) by verifying the metadata structure.
func TestCollectGoMetadata_VerifyContent(t *testing.T) {
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/github.com/example/mod/@v/list", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("v1.0.0\nv1.0.1\n"))
	})
	proxyMux.HandleFunc("/github.com/example/mod/@v/v1.0.1.info", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"Version": "v1.0.1",
			"Time":    "2024-06-01T12:00:00Z",
		})
	})
	proxyMux.HandleFunc("/github.com/example/mod/@v/v1.0.1.mod", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("module github.com/example/mod\n\ngo 1.22\n"))
	})
	proxyMux.HandleFunc("/github.com/example/mod/@v/v1.0.0.mod", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("module github.com/example/mod\n\ngo 1.21\n"))
	})
	proxySrv := httptest.NewServer(proxyMux)
	defer proxySrv.Close()

	mock := &mockProvider{response: `{"block":false,"summary":"ok","findings":[]}`}
	ra := NewReleaseAnalyzer(mock, "", "", map[string]string{"go": proxySrv.URL})
	_, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "go",
		Module:    "github.com/example/mod",
		Version:   "v1.0.1",
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	prompt := mock.lastRequest.UserPrompt

	// Version list must be present
	if !strings.Contains(prompt, "v1.0.0") || !strings.Contains(prompt, "v1.0.1") {
		t.Error("expected version list in metadata prompt")
	}
	// Version info must be present
	if !strings.Contains(prompt, "Version info") {
		t.Error("expected version info section in metadata prompt")
	}
	// Current go.mod must be present
	if !strings.Contains(prompt, "go 1.22") {
		t.Error("expected current go.mod content in metadata prompt")
	}
	// Previous version go.mod must be present
	if !strings.Contains(prompt, "go 1.21") {
		t.Error("expected previous version go.mod content in metadata prompt")
	}
}

// TestCollectGoMetadata_ErrorContent verifies that error messages are included
// in metadata when endpoints fail.
func TestCollectGoMetadata_ErrorContent(t *testing.T) {
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/mod/@v/list", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	proxyMux.HandleFunc("/mod/@v/v1.0.1.info", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	})
	proxyMux.HandleFunc("/mod/@v/v1.0.1.mod", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	})
	// guessPreviousTag("v1.0.1") = "v1.0.0", so this would be tried
	proxyMux.HandleFunc("/mod/@v/v1.0.0.mod", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	})
	proxySrv := httptest.NewServer(proxyMux)
	defer proxySrv.Close()

	mock := &mockProvider{response: `{"block":false,"summary":"ok","findings":[]}`}
	ra := NewReleaseAnalyzer(mock, "", "", map[string]string{"go": proxySrv.URL})
	_, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "go",
		Module:    "mod",
		Version:   "v1.0.1",
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	prompt := mock.lastRequest.UserPrompt
	// Error messages should be embedded in the metadata
	if !strings.Contains(prompt, "error") {
		t.Error("expected error messages in metadata when endpoints fail")
	}
}

// TestCollectNpmMetadata_VerifyContent verifies npm metadata content.
// Kills mutants in collectNpmMetadata (lines 180-220).
func TestCollectNpmMetadata_VerifyContent(t *testing.T) {
	npmMux := http.NewServeMux()
	npmMux.HandleFunc("/my-pkg", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"name": "my-pkg",
			"time": map[string]string{
				"1.0.0":    "2024-01-01T00:00:00Z",
				"1.0.1":    "2024-06-01T00:00:00Z",
				"created":  "2024-01-01T00:00:00Z",
				"modified": "2024-06-01T00:00:00Z",
			},
			"maintainers": []map[string]string{
				{"name": "alice", "email": "alice@example.com"},
			},
			"versions": map[string]any{
				"1.0.0": map[string]any{
					"dependencies": map[string]string{"lodash": "^4.0.0"},
				},
				"1.0.1": map[string]any{
					"dependencies": map[string]string{"lodash": "^4.1.0"},
				},
			},
			"repository": map[string]string{"url": ""},
		})
	})
	npmSrv := httptest.NewServer(npmMux)
	defer npmSrv.Close()

	mock := &mockProvider{response: `{"block":false,"summary":"ok","findings":[]}`}
	ra := NewReleaseAnalyzer(mock, "", "", map[string]string{"npm": npmSrv.URL})
	_, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "npm",
		Module:    "my-pkg",
		Version:   "1.0.1",
	})
	if err != nil {
		t.Fatalf("Analyze npm: %v", err)
	}

	prompt := mock.lastRequest.UserPrompt
	if !strings.Contains(prompt, "alice") {
		t.Error("expected maintainer name in npm metadata")
	}
	if !strings.Contains(prompt, "lodash") {
		t.Error("expected dependency in npm metadata")
	}
	if !strings.Contains(prompt, "npm") {
		t.Error("expected npm registry header in metadata")
	}
}

// TestCollectPipMetadata_VerifyContent verifies PyPI metadata content.
// Kills mutants in collectPipMetadata (lines 274-285).
func TestCollectPipMetadata_VerifyContent(t *testing.T) {
	pipMux := http.NewServeMux()
	pipMux.HandleFunc("/pypi/mypackage/json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"info": map[string]any{
				"name":         "mypackage",
				"author":       "Bob",
				"author_email": "bob@example.com",
				"requires_dist": []string{"requests>=2.0"},
				"project_urls":  map[string]string{},
			},
			"releases": map[string]any{
				"1.0.0": []map[string]string{
					{"upload_time_iso_8601": "2024-01-01T00:00:00Z"},
				},
				"1.0.1": []map[string]string{
					{"upload_time_iso_8601": "2024-06-01T00:00:00Z"},
				},
			},
		})
	})
	pipSrv := httptest.NewServer(pipMux)
	defer pipSrv.Close()

	mock := &mockProvider{response: `{"block":false,"summary":"ok","findings":[]}`}
	ra := NewReleaseAnalyzer(mock, "", "", map[string]string{"pip": pipSrv.URL})
	_, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "pip",
		Module:    "mypackage",
		Version:   "1.0.1",
	})
	if err != nil {
		t.Fatalf("Analyze pip: %v", err)
	}

	prompt := mock.lastRequest.UserPrompt
	if !strings.Contains(prompt, "Bob") {
		t.Error("expected author in pip metadata")
	}
	if !strings.Contains(prompt, "requests") {
		t.Error("expected dependency in pip metadata")
	}
	if !strings.Contains(prompt, "PyPI") {
		t.Error("expected PyPI header in metadata")
	}
}

// TestCollectRubyGemsMetadata_VerifyContent verifies RubyGems metadata content.
// Kills mutants in collectRubyGemsMetadata (lines 322-361).
func TestCollectRubyGemsMetadata_VerifyContent(t *testing.T) {
	gemMux := http.NewServeMux()
	gemMux.HandleFunc("/api/v1/versions/mygem.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"number": "1.0.0", "created_at": "2024-01-01T00:00:00Z", "authors": "Charlie"},
			{"number": "1.0.1", "created_at": "2024-06-01T00:00:00Z", "authors": "Charlie"},
		})
	})
	gemMux.HandleFunc("/api/v2/rubygems/mygem/versions/1.0.1.json", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"authors":         "Charlie",
			"description":     "A test gem",
			"source_code_uri": "",
			"dependencies": map[string]any{
				"runtime": []map[string]any{
					{"name": "rake", "requirements": ">= 12.0"},
				},
			},
		})
	})
	gemSrv := httptest.NewServer(gemMux)
	defer gemSrv.Close()

	mock := &mockProvider{response: `{"block":false,"summary":"ok","findings":[]}`}
	ra := NewReleaseAnalyzer(mock, "", "", map[string]string{"rubygems": gemSrv.URL})
	_, err := ra.Analyze(context.Background(), AnalysisRequest{
		Ecosystem: "rubygems",
		Module:    "mygem",
		Version:   "1.0.1",
	})
	if err != nil {
		t.Fatalf("Analyze rubygems: %v", err)
	}

	prompt := mock.lastRequest.UserPrompt
	if !strings.Contains(prompt, "Charlie") {
		t.Error("expected author in rubygems metadata")
	}
	if !strings.Contains(prompt, "rake") {
		t.Error("expected runtime dependency in rubygems metadata")
	}
	if !strings.Contains(prompt, "RubyGems") {
		t.Error("expected RubyGems header in metadata")
	}
}
