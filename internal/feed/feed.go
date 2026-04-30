package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const csvURL = "https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv"
const osvAPIBase = "https://api.osv.dev/v1/vulns/"
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
