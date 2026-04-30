package feed

import (
	"bytes"
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
