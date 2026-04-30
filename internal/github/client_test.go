package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchRepoInfo(t *testing.T) {
	created := time.Date(2020, 6, 15, 10, 0, 0, 0, time.UTC)
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner1/repo1", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Bearer test-token, got %s", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"owner":            map[string]string{"login": "owner1"},
			"stargazers_count": 1500,
			"forks_count":      120,
			"created_at":       created.Format(time.RFC3339),
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	info, err := c.FetchRepoInfo(context.Background(), "owner1", "repo1")
	if err != nil {
		t.Fatalf("FetchRepoInfo: %v", err)
	}

	if info.Owner != "owner1" {
		t.Errorf("Owner = %q, want %q", info.Owner, "owner1")
	}
	if info.Stars != 1500 {
		t.Errorf("Stars = %d, want 1500", info.Stars)
	}
	if info.Forks != 120 {
		t.Errorf("Forks = %d, want 120", info.Forks)
	}
	if !info.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v", info.CreatedAt, created)
	}
}

func TestFetchContributors(t *testing.T) {
	user1Created := time.Date(2018, 1, 10, 0, 0, 0, 0, time.UTC)
	user2Created := time.Date(2023, 11, 5, 0, 0, 0, 0, time.UTC)

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner1/repo1/contributors", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"login": "alice", "contributions": 50},
			{"login": "bob", "contributions": 5},
		})
	})
	mux.HandleFunc("/users/alice", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"created_at":  user1Created.Format(time.RFC3339),
			"public_repos": 30,
		})
	})
	mux.HandleFunc("/users/bob", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"created_at":  user2Created.Format(time.RFC3339),
			"public_repos": 2,
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	contribs, err := c.FetchContributors(context.Background(), "owner1", "repo1")
	if err != nil {
		t.Fatalf("FetchContributors: %v", err)
	}

	if len(contribs) != 2 {
		t.Fatalf("len(contribs) = %d, want 2", len(contribs))
	}

	// Alice
	if contribs[0].Login != "alice" {
		t.Errorf("contribs[0].Login = %q, want %q", contribs[0].Login, "alice")
	}
	if contribs[0].Contributions != 50 {
		t.Errorf("contribs[0].Contributions = %d, want 50", contribs[0].Contributions)
	}
	if !contribs[0].CreatedAt.Equal(user1Created) {
		t.Errorf("contribs[0].CreatedAt = %v, want %v", contribs[0].CreatedAt, user1Created)
	}
	if contribs[0].PublicRepos != 30 {
		t.Errorf("contribs[0].PublicRepos = %d, want 30", contribs[0].PublicRepos)
	}

	// Bob
	if contribs[1].Login != "bob" {
		t.Errorf("contribs[1].Login = %q, want %q", contribs[1].Login, "bob")
	}
	if contribs[1].Contributions != 5 {
		t.Errorf("contribs[1].Contributions = %d, want 5", contribs[1].Contributions)
	}
	if !contribs[1].CreatedAt.Equal(user2Created) {
		t.Errorf("contribs[1].CreatedAt = %v, want %v", contribs[1].CreatedAt, user2Created)
	}
	if contribs[1].PublicRepos != 2 {
		t.Errorf("contribs[1].PublicRepos = %d, want 2", contribs[1].PublicRepos)
	}
}

func TestFetchCompare(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner1/repo1/compare/v1.0.0...v1.0.1", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_commits": 3,
			"files": []map[string]interface{}{
				{"filename": "main.go", "additions": 10, "deletions": 2},
				{"filename": "lib.go", "additions": 5, "deletions": 0},
			},
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	cmp, err := c.FetchCompare(context.Background(), "owner1", "repo1", "v1.0.0", "v1.0.1")
	if err != nil {
		t.Fatalf("FetchCompare: %v", err)
	}

	if cmp.TotalCommits != 3 {
		t.Errorf("TotalCommits = %d, want 3", cmp.TotalCommits)
	}
	if len(cmp.Files) != 2 {
		t.Fatalf("len(Files) = %d, want 2", len(cmp.Files))
	}
	if cmp.Files[0].Filename != "main.go" {
		t.Errorf("Files[0].Filename = %q, want %q", cmp.Files[0].Filename, "main.go")
	}
	if cmp.Files[0].Additions != 10 {
		t.Errorf("Files[0].Additions = %d, want 10", cmp.Files[0].Additions)
	}
	if cmp.Files[0].Deletions != 2 {
		t.Errorf("Files[0].Deletions = %d, want 2", cmp.Files[0].Deletions)
	}
	if cmp.Files[1].Filename != "lib.go" {
		t.Errorf("Files[1].Filename = %q, want %q", cmp.Files[1].Filename, "lib.go")
	}
}

func TestClientNoToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner1/repo1", func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("expected no Authorization header, got %q", auth)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"owner":            map[string]string{"login": "owner1"},
			"stargazers_count": 10,
			"forks_count":      1,
			"created_at":       "2024-01-01T00:00:00Z",
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL, "")
	_, err := c.FetchRepoInfo(context.Background(), "owner1", "repo1")
	if err != nil {
		t.Fatalf("FetchRepoInfo without token: %v", err)
	}
}

func TestClientTimeout(t *testing.T) {
	// The client timeout is 30 * time.Second. If the arithmetic mutant changes
	// this to 30 + time.Second (= 31ns) or 30 / time.Second (= 0), then a
	// request to a server that introduces a small delay will fail.
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner1/repo1", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"owner":            map[string]string{"login": "owner1"},
			"stargazers_count": 42,
			"forks_count":      7,
			"created_at":       "2024-01-01T00:00:00Z",
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	info, err := c.FetchRepoInfo(context.Background(), "owner1", "repo1")
	if err != nil {
		t.Fatalf("FetchRepoInfo should succeed with 30s timeout, got error: %v", err)
	}
	if info.Stars != 42 {
		t.Errorf("Stars = %d, want 42", info.Stars)
	}
}

func TestNewClientDefaultBaseURL(t *testing.T) {
	c := NewClient("", "tok")
	if c.baseURL != "https://api.github.com" {
		t.Errorf("expected default baseURL %q, got %q", "https://api.github.com", c.baseURL)
	}
}

func TestNewClientTrimsTrailingSlash(t *testing.T) {
	c := NewClient("https://api.github.com/", "tok")
	if c.baseURL != "https://api.github.com" {
		t.Errorf("expected baseURL without trailing slash, got %q", c.baseURL)
	}
}
