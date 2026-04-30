package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const csvURL = "https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv"
const osvAPIBase = "https://api.osv.dev/v1/vulns/"
const ghGraphQLURL = "https://api.github.com/graphql"
const rangeBytes = 51200 // 50KB

// MALEntry is a parsed line from modified_id.csv.
type MALEntry struct {
	Modified  time.Time
	Ecosystem string // "npm", "PyPI", etc.
	ID        string // "MAL-2025-49286"
}

// parseMALEntries parses CSV bytes and returns MAL entries newer than since.
// The CSV is reverse-chronological, so we stop early once entries are too old.
func parseMALEntries(data []byte, since time.Time) []MALEntry {
	var entries []MALEntry
	for _, line := range bytes.Split(data, []byte("\n")) {
		s := strings.TrimSpace(string(line))
		if s == "" {
			continue
		}
		comma := strings.IndexByte(s, ',')
		if comma < 0 {
			continue
		}
		ts, ref := s[:comma], s[comma+1:]
		if !strings.Contains(ref, "/MAL-") {
			continue
		}
		modified, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		if !since.IsZero() && !modified.After(since) {
			break // CSV is reverse-chronological; all remaining entries are older
		}
		slash := strings.IndexByte(ref, '/')
		if slash < 0 {
			continue
		}
		entries = append(entries, MALEntry{
			Modified:  modified,
			Ecosystem: ref[:slash],
			ID:        ref[slash+1:],
		})
	}
	return entries
}

// Advisory holds parsed osv.dev vulnerability data.
type Advisory struct {
	ID       string            `json:"id"`
	Summary  string            `json:"summary"`
	Modified time.Time         `json:"modified"`
	Affected []AffectedPackage `json:"affected"`
}

// AffectedPackage is one affected entry from an osv.dev advisory.
type AffectedPackage struct {
	Package  osvPackage `json:"package"`
	Versions []string   `json:"versions"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

// fetchRecentMALIDs fetches the first rangeBytes of csvURL and returns MAL entries newer than since.
func fetchRecentMALIDs(ctx context.Context, csvEndpoint string, since time.Time) ([]MALEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, csvEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", rangeBytes-1))

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Accept 200 (full content) or 206 (partial content)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseMALEntries(data, since), nil
}

// fetchAdvisory fetches a single advisory by ID from osv.dev.
func fetchAdvisory(ctx context.Context, apiBase string, id string) (Advisory, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+id, nil)
	if err != nil {
		return Advisory{}, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return Advisory{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Advisory{}, fmt.Errorf("osv.dev returned %d for %s", resp.StatusCode, id)
	}

	var adv Advisory
	if err := json.NewDecoder(resp.Body).Decode(&adv); err != nil {
		return Advisory{}, fmt.Errorf("decoding advisory %s: %w", id, err)
	}
	return adv, nil
}

// ghsaQuery is the GraphQL query for fetching recent MALWARE advisories.
const ghsaQuery = `query($since: DateTime!, $cursor: String) {
  securityAdvisories(classifications: [MALWARE], first: 50, orderBy: {field: PUBLISHED_AT, direction: DESC}, publishedSince: $since, after: $cursor) {
    nodes {
      ghsaId
      summary
      publishedAt
      vulnerabilities(first: 20) {
        nodes {
          package { ecosystem name }
          vulnerableVersionRange
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}`

type ghsaResponse struct {
	Data struct {
		SecurityAdvisories struct {
			Nodes []struct {
				GhsaID      string    `json:"ghsaId"`
				Summary     string    `json:"summary"`
				PublishedAt time.Time `json:"publishedAt"`
				Vulnerabilities struct {
					Nodes []struct {
						Package struct {
							Ecosystem string `json:"ecosystem"`
							Name      string `json:"name"`
						} `json:"package"`
						VulnerableVersionRange string `json:"vulnerableVersionRange"`
					} `json:"nodes"`
				} `json:"vulnerabilities"`
			} `json:"nodes"`
			PageInfo struct {
				HasNextPage bool   `json:"hasNextPage"`
				EndCursor   string `json:"endCursor"`
			} `json:"pageInfo"`
		} `json:"securityAdvisories"`
	} `json:"data"`
}

// ghsaEcosystem maps GitHub ecosystem names to osv.dev-style names.
func ghsaEcosystem(gh string) string {
	switch gh {
	case "NPM":
		return "npm"
	case "PIP":
		return "PyPI"
	case "GO":
		return "Go"
	case "RUBYGEMS":
		return "RubyGems"
	default:
		return gh
	}
}

// fetchGHSAMalware queries GitHub Advisory Database for MALWARE advisories published after since.
// Returns them as Advisory structs compatible with the MAL-* output.
func fetchGHSAMalware(ctx context.Context, token string, graphqlURL string, since time.Time) ([]Advisory, error) {
	if graphqlURL == "" {
		graphqlURL = ghGraphQLURL
	}

	var advisories []Advisory
	var cursor *string

	for {
		vars := map[string]interface{}{
			"since": since.Format(time.RFC3339),
		}
		if cursor != nil {
			vars["cursor"] = *cursor
		}

		body, _ := json.Marshal(map[string]interface{}{
			"query":     ghsaQuery,
			"variables": vars,
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, graphqlURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		var result ghsaResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decoding GHSA response: %w", err)
		}

		for _, node := range result.Data.SecurityAdvisories.Nodes {
			adv := Advisory{
				ID:       node.GhsaID,
				Summary:  node.Summary,
				Modified: node.PublishedAt,
			}
			for _, vuln := range node.Vulnerabilities.Nodes {
				// Parse version from "= 2.0.7" format
				ver := strings.TrimPrefix(vuln.VulnerableVersionRange, "= ")
				adv.Affected = append(adv.Affected, AffectedPackage{
					Package:  osvPackage{Ecosystem: ghsaEcosystem(vuln.Package.Ecosystem), Name: vuln.Package.Name},
					Versions: []string{ver},
				})
			}
			advisories = append(advisories, adv)
		}

		if !result.Data.SecurityAdvisories.PageInfo.HasNextPage {
			break
		}
		cursor = &result.Data.SecurityAdvisories.PageInfo.EndCursor
	}

	return advisories, nil
}

// normalizeEcosystem maps user input to osv.dev ecosystem names.
func normalizeEcosystem(s string) string {
	switch strings.ToLower(s) {
	case "npm":
		return "npm"
	case "pypi", "pip":
		return "PyPI"
	case "go", "golang":
		return "Go"
	case "rubygems", "gem":
		return "RubyGems"
	default:
		return s
	}
}

// filterByEcosystem returns entries matching any of the given ecosystems.
// If ecosystems is empty, all entries are returned.
func filterByEcosystem(entries []MALEntry, ecosystems []string) []MALEntry {
	if len(ecosystems) == 0 {
		return entries
	}
	allowed := make(map[string]bool, len(ecosystems))
	for _, e := range ecosystems {
		allowed[normalizeEcosystem(e)] = true
	}
	var filtered []MALEntry
	for _, entry := range entries {
		if allowed[entry.Ecosystem] {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

type feedState struct {
	LastSeen time.Time `json:"last_seen"`
}

func loadState(path string) time.Time {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	var s feedState
	if json.Unmarshal(data, &s) != nil {
		return time.Time{}
	}
	return s.LastSeen
}

func saveState(path string, lastSeen time.Time) {
	data, _ := json.Marshal(feedState{LastSeen: lastSeen})
	os.WriteFile(path, data, 0644)
}

const (
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorDim    = "\033[2m"
	colorReset  = "\033[0m"
)

// renderAdvisory writes a formatted advisory block to w.
// If plain is true, ANSI codes are omitted.
func renderAdvisory(w io.Writer, adv Advisory, plain bool) {
	c := func(code, s string) string {
		if plain {
			return s
		}
		return code + s + colorReset
	}

	for _, aff := range adv.Affected {
		versions := strings.Join(aff.Versions, ", ")
		if len(versions) > 60 {
			versions = versions[:57] + "..."
		}
		pkg := aff.Package.Name
		if versions != "" {
			pkg += "@" + versions
		}

		fmt.Fprintf(w, "[%s] %s / %s\n",
			c(colorRed, adv.ID),
			c(colorYellow, aff.Package.Ecosystem),
			c(colorCyan, pkg))
	}
	if len(adv.Affected) == 0 {
		fmt.Fprintf(w, "[%s]\n", c(colorRed, adv.ID))
	}

	if adv.Summary != "" {
		fmt.Fprintf(w, "  %s\n", adv.Summary)
	}

	date := adv.Modified.Format("2006-01-02")
	link := "https://osv.dev/vulnerability/" + adv.ID
	if strings.HasPrefix(adv.ID, "GHSA-") {
		link = "https://github.com/advisories/" + adv.ID
	}
	fmt.Fprintf(w, "  %s  %s\n", c(colorDim, date), c(colorDim, link))
	fmt.Fprintln(w, "---")
}

// Config holds feed configuration.
type Config struct {
	Interval    time.Duration
	Ecosystems  []string
	StatePath   string
	GithubToken string // optional; enables GHSA MALWARE feed
	// Overridable endpoints for testing.
	csvURL       string
	osvAPIBase   string
	ghGraphqlURL string
}

func (c Config) getCSVURL() string {
	if c.csvURL != "" {
		return c.csvURL
	}
	return csvURL
}

func (c Config) getOSVAPIBase() string {
	if c.osvAPIBase != "" {
		return c.osvAPIBase
	}
	return osvAPIBase
}

// filterGHSAByEcosystem filters GHSA advisories by ecosystem.
// If ecosystems is empty, all advisories are returned.
func filterGHSAByEcosystem(advisories []Advisory, ecosystems []string) []Advisory {
	if len(ecosystems) == 0 {
		return advisories
	}
	allowed := make(map[string]bool, len(ecosystems))
	for _, e := range ecosystems {
		allowed[normalizeEcosystem(e)] = true
	}
	var filtered []Advisory
	for _, adv := range advisories {
		for _, aff := range adv.Affected {
			if allowed[aff.Package.Ecosystem] {
				filtered = append(filtered, adv)
				break
			}
		}
	}
	return filtered
}

// dedup returns advisories that don't overlap with MAL entries by package name+ecosystem.
func dedup(ghsaAdvs []Advisory, malAdvs []Advisory) []Advisory {
	seen := make(map[string]bool)
	for _, adv := range malAdvs {
		for _, aff := range adv.Affected {
			seen[aff.Package.Ecosystem+"/"+aff.Package.Name] = true
		}
	}
	var unique []Advisory
	for _, adv := range ghsaAdvs {
		dup := false
		for _, aff := range adv.Affected {
			if seen[aff.Package.Ecosystem+"/"+aff.Package.Name] {
				dup = true
				break
			}
		}
		if !dup {
			unique = append(unique, adv)
		}
	}
	return unique
}

// Run starts the feed poll loop. It performs one poll immediately, then
// repeats every cfg.Interval. It blocks until ctx is cancelled.
func Run(ctx context.Context, cfg Config, w io.Writer, plain bool) error {
	lastSeen := loadState(cfg.StatePath)
	if lastSeen.IsZero() {
		lastSeen = time.Now().Add(-24 * time.Hour)
	}

	poll := func() {
		// Source 1: osv.dev MAL-*
		var malAdvs []Advisory
		entries, err := fetchRecentMALIDs(ctx, cfg.getCSVURL(), lastSeen)
		if err != nil {
			log.Printf("[feed] error fetching CSV: %v", err)
		} else {
			entries = filterByEcosystem(entries, cfg.Ecosystems)
			for _, entry := range entries {
				adv, err := fetchAdvisory(ctx, cfg.getOSVAPIBase(), entry.ID)
				if err != nil {
					log.Printf("[feed] error fetching %s: %v", entry.ID, err)
					continue
				}
				malAdvs = append(malAdvs, adv)
			}
		}

		// Source 2: GHSA MALWARE (optional, needs token)
		var ghsaAdvs []Advisory
		if cfg.GithubToken != "" {
			ghsa, err := fetchGHSAMalware(ctx, cfg.GithubToken, cfg.ghGraphqlURL, lastSeen)
			if err != nil {
				log.Printf("[feed] error fetching GHSA: %v", err)
			} else {
				ghsaAdvs = filterGHSAByEcosystem(ghsa, cfg.Ecosystems)
				ghsaAdvs = dedup(ghsaAdvs, malAdvs)
			}
		}

		all := append(malAdvs, ghsaAdvs...)
		if len(all) == 0 {
			return
		}

		// Render and track newest timestamp
		newest := lastSeen
		for _, adv := range all {
			renderAdvisory(w, adv, plain)
			if adv.Modified.After(newest) {
				newest = adv.Modified
			}
		}

		if newest.After(lastSeen) {
			lastSeen = newest
			saveState(cfg.StatePath, lastSeen)
		}
	}

	// First poll immediately
	poll()

	if cfg.Interval <= 0 {
		return ctx.Err()
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			poll()
		}
	}
}
