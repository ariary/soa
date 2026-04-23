package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client provides access to the GitHub API.
type Client struct {
	baseURL string
	token   string
	client  *http.Client
}

// RepoInfo holds summary data about a GitHub repository.
type RepoInfo struct {
	Owner     string
	Stars     int
	Forks     int
	CreatedAt time.Time
}

// Contributor holds data about a repository contributor including their
// account age and public repository count (fetched separately).
type Contributor struct {
	Login         string
	Contributions int
	CreatedAt     time.Time
	PublicRepos   int
}

// CompareResult holds the result of comparing two git refs.
type CompareResult struct {
	TotalCommits int
	Files        []FileChange
}

// FileChange describes a single file that changed between two refs.
type FileChange struct {
	Filename  string
	Additions int
	Deletions int
}

// NewClient creates a GitHub API client. If baseURL is empty it defaults to
// "https://api.github.com". The token is optional; when empty, requests are
// sent without an Authorization header.
func NewClient(baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	return &Client{
		baseURL: baseURL,
		token:   token,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// do executes a GET request against path, decodes the JSON response into
// target, and returns any error.
func (c *Client) do(ctx context.Context, path string, target interface{}) error {
	url := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d for %s", resp.StatusCode, path)
	}

	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

// FetchRepoInfo returns summary information about a repository.
func (c *Client) FetchRepoInfo(ctx context.Context, owner, repo string) (RepoInfo, error) {
	path := fmt.Sprintf("/repos/%s/%s", owner, repo)

	var raw struct {
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
		StargazersCount int       `json:"stargazers_count"`
		ForksCount      int       `json:"forks_count"`
		CreatedAt       time.Time `json:"created_at"`
	}

	if err := c.do(ctx, path, &raw); err != nil {
		return RepoInfo{}, err
	}

	return RepoInfo{
		Owner:     raw.Owner.Login,
		Stars:     raw.StargazersCount,
		Forks:     raw.ForksCount,
		CreatedAt: raw.CreatedAt,
	}, nil
}

// FetchContributors returns the contributors for a repository, enriched with
// account age and public repo count from the user profile endpoint.
func (c *Client) FetchContributors(ctx context.Context, owner, repo string) ([]Contributor, error) {
	path := fmt.Sprintf("/repos/%s/%s/contributors", owner, repo)

	var rawContribs []struct {
		Login         string `json:"login"`
		Contributions int    `json:"contributions"`
	}
	if err := c.do(ctx, path, &rawContribs); err != nil {
		return nil, err
	}

	contributors := make([]Contributor, 0, len(rawContribs))
	for _, rc := range rawContribs {
		var user struct {
			CreatedAt   time.Time `json:"created_at"`
			PublicRepos int       `json:"public_repos"`
		}
		userPath := fmt.Sprintf("/users/%s", rc.Login)
		if err := c.do(ctx, userPath, &user); err != nil {
			// Best-effort: skip enrichment on error.
			contributors = append(contributors, Contributor{
				Login:         rc.Login,
				Contributions: rc.Contributions,
			})
			continue
		}
		contributors = append(contributors, Contributor{
			Login:         rc.Login,
			Contributions: rc.Contributions,
			CreatedAt:     user.CreatedAt,
			PublicRepos:   user.PublicRepos,
		})
	}

	return contributors, nil
}

// FetchCompare compares two git refs and returns the commits and changed files.
func (c *Client) FetchCompare(ctx context.Context, owner, repo, base, head string) (CompareResult, error) {
	path := fmt.Sprintf("/repos/%s/%s/compare/%s...%s", owner, repo, base, head)

	var raw struct {
		TotalCommits int `json:"total_commits"`
		Files        []struct {
			Filename  string `json:"filename"`
			Additions int    `json:"additions"`
			Deletions int    `json:"deletions"`
		} `json:"files"`
	}

	if err := c.do(ctx, path, &raw); err != nil {
		return CompareResult{}, err
	}

	files := make([]FileChange, len(raw.Files))
	for i, f := range raw.Files {
		files[i] = FileChange{
			Filename:  f.Filename,
			Additions: f.Additions,
			Deletions: f.Deletions,
		}
	}

	return CompareResult{
		TotalCommits: raw.TotalCommits,
		Files:        files,
	}, nil
}
