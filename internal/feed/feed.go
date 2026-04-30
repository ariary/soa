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
	"sync"
	"time"
)

// InfoLevel controls the detail level of advisory output.
type InfoLevel int

const (
	InfoDefault InfoLevel = iota // current baseline: ID + summary + date/link
	InfoShort                    // minimal: ID + ecosystem/package only
	InfoFull                     // everything: all available fields
)

// RenderConfig controls advisory output formatting.
type RenderConfig struct {
	Plain     bool
	Level     InfoLevel
	OSVFields []string // extra OSV fields to display from raw JSON
}

const csvURL = "https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv"
const osvAPIBase = "https://api.osv.dev/v1/vulns/"
const ghGraphQLURL = "https://api.github.com/graphql"
const defaultRangeBytes = 51200         // 50KB — covers ~5 hours at current CSV density
const maxRangeBytes = 10 * 1024 * 1024  // 10MB cap
const fetchWorkers = 20                 // concurrent osv.dev API requests

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

// Advisory holds parsed osv.dev vulnerability data (OSV schema).
type Advisory struct {
	ID         string            `json:"id"`
	Summary    string            `json:"summary"`
	Details    string            `json:"details"`
	Aliases    []string          `json:"aliases"`
	Modified   time.Time         `json:"modified"`
	Published  time.Time         `json:"published"`
	Withdrawn  *time.Time        `json:"withdrawn"`
	Affected   []AffectedPackage `json:"affected"`
	References []Reference       `json:"references"`
	Raw        json.RawMessage   `json:"-"` // full OSV JSON for --osv-field extraction
}

// Reference is a link associated with an advisory.
type Reference struct {
	Type string `json:"type"` // ADVISORY, PACKAGE, WEB, etc.
	URL  string `json:"url"`
}

// AffectedPackage is one affected entry from an osv.dev advisory.
type AffectedPackage struct {
	Package  osvPackage     `json:"package"`
	Versions []string       `json:"versions"`
	Ranges   []VersionRange `json:"ranges"`
}

// VersionRange describes affected version ranges (SEMVER, ECOSYSTEM, or GIT).
type VersionRange struct {
	Type   string       `json:"type"`
	Events []RangeEvent `json:"events"`
}

// RangeEvent is a single event in a version range.
type RangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

// rangeBytesForWindow returns how many bytes of the CSV to fetch based on
// the lookback duration. The CSV has ~200 lines/hour at ~55 bytes/line.
// We add a 2x margin to account for bursts.
func rangeBytesForWindow(since time.Time) int {
	hours := time.Since(since).Hours()
	if hours < 1 {
		hours = 1
	}
	n := int(hours * 200 * 55 * 2)
	if n < defaultRangeBytes {
		return defaultRangeBytes
	}
	if n > maxRangeBytes {
		return maxRangeBytes
	}
	return n
}

// fetchRecentMALIDs fetches the CSV and returns MAL entries newer than since.
// The byte range scales with the lookback window.
func fetchRecentMALIDs(ctx context.Context, csvEndpoint string, since time.Time) ([]MALEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, csvEndpoint, nil)
	if err != nil {
		return nil, err
	}
	rb := rangeBytesForWindow(since)
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", rb-1))

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

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return Advisory{}, fmt.Errorf("reading advisory %s: %w", id, err)
	}
	var adv Advisory
	if err := json.Unmarshal(data, &adv); err != nil {
		return Advisory{}, fmt.Errorf("decoding advisory %s: %w", id, err)
	}
	adv.Raw = json.RawMessage(data)
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
				ID:        node.GhsaID,
				Summary:   node.Summary,
				Modified:  node.PublishedAt,
				Published: node.PublishedAt,
			}
			for _, vuln := range node.Vulnerabilities.Nodes {
				pkg := AffectedPackage{
					Package: osvPackage{Ecosystem: ghsaEcosystem(vuln.Package.Ecosystem), Name: vuln.Package.Name},
				}
				vr := strings.TrimSpace(vuln.VulnerableVersionRange)
				if strings.HasPrefix(vr, "= ") {
					pkg.Versions = []string{strings.TrimSpace(vr[2:])}
				} else if vr != "" {
					pkg.Ranges = []VersionRange{parseGHSARange(vr)}
				}
				adv.Affected = append(adv.Affected, pkg)
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

// parseGHSARange converts a GHSA vulnerableVersionRange string into an OSV VersionRange.
func parseGHSARange(s string) VersionRange {
	vr := VersionRange{Type: "ECOSYSTEM"}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, ">= "):
			vr.Events = append(vr.Events, RangeEvent{Introduced: strings.TrimSpace(part[3:])})
		case strings.HasPrefix(part, "> "):
			vr.Events = append(vr.Events, RangeEvent{Introduced: strings.TrimSpace(part[2:])})
		case strings.HasPrefix(part, "<= "):
			vr.Events = append(vr.Events, RangeEvent{LastAffected: strings.TrimSpace(part[3:])})
		case strings.HasPrefix(part, "< "):
			vr.Events = append(vr.Events, RangeEvent{Fixed: strings.TrimSpace(part[2:])})
		}
	}
	return vr
}

// formatRanges returns a human-readable string for version ranges.
func formatRanges(ranges []VersionRange) string {
	var parts []string
	for _, r := range ranges {
		var introduced, upper string
		for _, e := range r.Events {
			if e.Introduced != "" {
				introduced = e.Introduced
			}
			if e.Fixed != "" {
				upper = e.Fixed
			}
			if e.LastAffected != "" {
				upper = e.LastAffected
			}
		}
		switch {
		case introduced == "0" && upper == "":
			parts = append(parts, "all versions")
		case introduced != "" && upper != "":
			parts = append(parts, ">= "+introduced+", < "+upper)
		case introduced != "":
			parts = append(parts, ">= "+introduced)
		case upper != "":
			parts = append(parts, "< "+upper)
		}
	}
	return strings.Join(parts, "; ")
}

// firstLine returns the first meaningful line of s, skipping YAML frontmatter.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "---") {
		if end := strings.Index(s[3:], "---"); end >= 0 {
			s = strings.TrimSpace(s[3+end+3:])
		}
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// advisoryLink returns the best URL for an advisory.
func advisoryLink(adv Advisory) string {
	for _, ref := range adv.References {
		if ref.Type == "ADVISORY" {
			return ref.URL
		}
	}
	if strings.HasPrefix(adv.ID, "GHSA-") {
		return "https://github.com/advisories/" + adv.ID
	}
	return "https://osv.dev/vulnerability/" + adv.ID
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

// extractRawField extracts a top-level field from raw JSON.
func extractRawField(raw json.RawMessage, field string) (json.RawMessage, bool) {
	if raw == nil {
		return nil, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false
	}
	val, ok := m[field]
	if !ok || string(val) == "null" {
		return nil, false
	}
	return val, true
}

// formatOSVField formats a raw JSON field value for display.
func formatOSVField(field string, raw json.RawMessage) string {
	switch field {
	case "details":
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return strings.ReplaceAll(s, "\n", " ")
		}
	case "aliases", "related":
		var arr []string
		if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
			return strings.Join(arr, ", ")
		}
	case "severity":
		var sevs []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		}
		if json.Unmarshal(raw, &sevs) == nil && len(sevs) > 0 {
			parts := make([]string, len(sevs))
			for i, s := range sevs {
				parts[i] = s.Type + ": " + s.Score
			}
			return strings.Join(parts, ", ")
		}
	case "references":
		var refs []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		}
		if json.Unmarshal(raw, &refs) == nil && len(refs) > 0 {
			lines := make([]string, len(refs))
			for i, r := range refs {
				lines[i] = fmt.Sprintf("    %s  %s", r.Type, r.URL)
			}
			return "\n" + strings.Join(lines, "\n")
		}
	case "credits":
		var credits []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &credits) == nil && len(credits) > 0 {
			parts := make([]string, len(credits))
			for i, cr := range credits {
				if cr.Type != "" {
					parts[i] = cr.Name + " (" + cr.Type + ")"
				} else {
					parts[i] = cr.Name
				}
			}
			return strings.Join(parts, ", ")
		}
	case "published", "withdrawn":
		var s string
		if json.Unmarshal(raw, &s) == nil {
			if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
				return t.Format("2006-01-02")
			}
			return s
		}
	}
	// Fallback: unquote strings, otherwise compact JSON
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

// renderAdvisory writes a formatted advisory block to w.
func renderAdvisory(w io.Writer, adv Advisory, rc RenderConfig) {
	c := func(code, s string) string {
		if rc.Plain {
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
		if rangeStr := formatRanges(aff.Ranges); rangeStr != "" {
			pkg += " (" + rangeStr + ")"
		}

		fmt.Fprintf(w, "[%s] %s / %s\n",
			c(colorRed, adv.ID),
			c(colorYellow, aff.Package.Ecosystem),
			c(colorCyan, pkg))
	}
	if len(adv.Affected) == 0 {
		fmt.Fprintf(w, "[%s]\n", c(colorRed, adv.ID))
	}

	// Default and Full: summary + date/link
	if rc.Level != InfoShort {
		summary := adv.Summary
		if summary == "" {
			summary = firstLine(adv.Details)
		}
		if summary != "" {
			fmt.Fprintf(w, "  %s\n", summary)
		}

		date := adv.Modified.Format("2006-01-02")
		if !adv.Published.IsZero() {
			date = adv.Published.Format("2006-01-02")
		}
		link := advisoryLink(adv)
		fmt.Fprintf(w, "  %s  %s\n", c(colorDim, date), c(colorDim, link))
	}

	// Full: extra struct fields
	if rc.Level == InfoFull {
		if adv.Details != "" && adv.Details != adv.Summary {
			details := strings.ReplaceAll(adv.Details, "\n", " ")
			fmt.Fprintf(w, "  %s: %s\n", c(colorDim, "details"), details)
		}
		if len(adv.Aliases) > 0 {
			fmt.Fprintf(w, "  %s: %s\n", c(colorDim, "aliases"), strings.Join(adv.Aliases, ", "))
		}
		if len(adv.References) > 0 {
			fmt.Fprintf(w, "  %s:\n", c(colorDim, "references"))
			for _, ref := range adv.References {
				fmt.Fprintf(w, "    %s  %s\n", ref.Type, ref.URL)
			}
		}
	}

	// Extra OSV fields from --osv-field
	for _, field := range rc.OSVFields {
		raw, ok := extractRawField(adv.Raw, field)
		if !ok {
			continue
		}
		rendered := formatOSVField(field, raw)
		if rendered == "" || rendered == "[]" || rendered == "null" {
			continue
		}
		if strings.HasPrefix(rendered, "\n") {
			fmt.Fprintf(w, "  %s:%s\n", c(colorDim, field), rendered)
		} else {
			fmt.Fprintf(w, "  %s: %s\n", c(colorDim, field), rendered)
		}
	}

	fmt.Fprintln(w, "---")
}

// Config holds feed configuration.
type Config struct {
	Interval    time.Duration
	Ecosystems  []string
	StatePath   string
	GithubToken string    // optional; enables GHSA MALWARE feed
	EnableOSV   bool      // poll osv.dev MAL-* feed
	EnableGHSA  bool      // poll GHSA MALWARE feed
	Since       time.Time // initial lookback; used when no state file exists
	InfoLevel   InfoLevel // output detail: InfoShort, InfoDefault, InfoFull
	OSVFields   []string  // extra OSV JSON fields to display
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

// dedup returns advisories that don't overlap with MAL entries by alias or package name+ecosystem.
func dedup(ghsaAdvs []Advisory, malAdvs []Advisory) []Advisory {
	seenPkg := make(map[string]bool)
	seenID := make(map[string]bool)
	for _, adv := range malAdvs {
		seenID[adv.ID] = true
		for _, alias := range adv.Aliases {
			seenID[alias] = true
		}
		for _, aff := range adv.Affected {
			seenPkg[aff.Package.Ecosystem+"/"+aff.Package.Name] = true
		}
	}
	var unique []Advisory
	for _, adv := range ghsaAdvs {
		if seenID[adv.ID] {
			continue
		}
		dup := false
		for _, aff := range adv.Affected {
			if seenPkg[aff.Package.Ecosystem+"/"+aff.Package.Name] {
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

// fetchAdvisories fetches full advisory details for the given MAL entries
// concurrently with bounded parallelism. Order is preserved.
func fetchAdvisories(ctx context.Context, apiBase string, entries []MALEntry) []Advisory {
	type result struct {
		adv Advisory
		err error
	}
	results := make([]result, len(entries))
	var wg sync.WaitGroup
	sem := make(chan struct{}, fetchWorkers)
	for i, entry := range entries {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			adv, err := fetchAdvisory(ctx, apiBase, id)
			results[i] = result{adv, err}
		}(i, entry.ID)
	}
	wg.Wait()

	var advs []Advisory
	for _, r := range results {
		if r.err != nil {
			if ctx.Err() == nil {
				log.Printf("[feed] error fetching advisory: %v", r.err)
			}
			continue
		}
		if r.adv.Withdrawn != nil {
			continue
		}
		advs = append(advs, r.adv)
	}
	return advs
}

// Run starts the feed poll loop. It performs one poll immediately, then
// repeats every cfg.Interval. It blocks until ctx is cancelled.
func Run(ctx context.Context, cfg Config, w io.Writer, plain bool) error {
	lastSeen := loadState(cfg.StatePath)
	if lastSeen.IsZero() && !cfg.Since.IsZero() {
		lastSeen = cfg.Since
	}
	if lastSeen.IsZero() {
		lastSeen = time.Now().Add(-24 * time.Hour)
	}

	poll := func() {
		// Source 1: osv.dev MAL-*
		var malAdvs []Advisory
		if cfg.EnableOSV {
			entries, err := fetchRecentMALIDs(ctx, cfg.getCSVURL(), lastSeen)
			if err != nil {
				log.Printf("[feed] error fetching CSV: %v", err)
			} else {
				entries = filterByEcosystem(entries, cfg.Ecosystems)
				if len(entries) > 0 {
					log.Printf("[feed] fetching %d MAL advisories...", len(entries))
				}
				malAdvs = fetchAdvisories(ctx, cfg.getOSVAPIBase(), entries)
			}
		}

		// Source 2: GHSA MALWARE (optional, needs token)
		var ghsaAdvs []Advisory
		if cfg.EnableGHSA && cfg.GithubToken != "" {
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
		rc := RenderConfig{Plain: plain, Level: cfg.InfoLevel, OSVFields: cfg.OSVFields}
		for _, adv := range all {
			renderAdvisory(w, adv, rc)
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
