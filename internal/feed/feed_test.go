package feed

import (
	"testing"
	"time"
)

func TestParseMALEntries(t *testing.T) {
	csv := `2026-04-30T15:37:33.526586Z,npm/MAL-2025-49286
2026-04-30T15:32:51.46441Z,npm/MAL-2026-3199
2026-04-30T15:31:38.253098Z,MinimOS/MINI-9xh5-38jf-44x8
2026-04-30T14:00:00Z,PyPI/MAL-2026-3100
2026-04-30T13:00:00Z,npm/MAL-2026-3050
`
	since := time.Date(2026, 4, 30, 14, 0, 0, 0, time.UTC)
	entries := parseMALEntries([]byte(csv), since)

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries newer than since, got %d", len(entries))
	}
	if entries[0].ID != "MAL-2025-49286" {
		t.Errorf("expected MAL-2025-49286, got %s", entries[0].ID)
	}
	if entries[0].Ecosystem != "npm" {
		t.Errorf("expected npm, got %s", entries[0].Ecosystem)
	}
	if entries[1].ID != "MAL-2026-3199" {
		t.Errorf("expected MAL-2026-3199, got %s", entries[1].ID)
	}
}

func TestParseMALEntries_SkipsNonMAL(t *testing.T) {
	csv := `2026-04-30T15:00:00Z,MinimOS/MINI-9xh5-38jf-44x8
2026-04-30T14:00:00Z,PyPI/GHSA-xqmj-j6mv-4862
`
	entries := parseMALEntries([]byte(csv), time.Time{})
	if len(entries) != 0 {
		t.Fatalf("expected 0 MAL entries, got %d", len(entries))
	}
}

func TestParseMALEntries_MalformedLines(t *testing.T) {
	csv := `bad line no comma
2026-04-30T15:00:00Z,npm/MAL-2026-3199
,
`
	entries := parseMALEntries([]byte(csv), time.Time{})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (skip malformed), got %d", len(entries))
	}
}
