package feed

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

func TestFetchRecentMALIDs(t *testing.T) {
	body := `2026-04-30T15:37:33.526586Z,npm/MAL-2025-49286
2026-04-30T15:32:51.46441Z,npm/MAL-2026-3199
2026-04-30T14:00:00Z,PyPI/GHSA-xqmj-j6mv-4862
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "" {
			t.Error("expected Range header")
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()

	since := time.Date(2026, 4, 30, 15, 0, 0, 0, time.UTC)
	entries, err := fetchRecentMALIDs(context.Background(), srv.URL, since)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2, got %d", len(entries))
	}
}

func TestFetchAdvisory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/MAL-2026-3199" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(`{
			"id": "MAL-2026-3199",
			"summary": "Malicious package",
			"modified": "2026-04-30T15:32:51Z",
			"affected": [{
				"package": {"ecosystem": "npm", "name": "blackbeards-navigator"},
				"versions": ["207.0.0", "208.0.0"]
			}]
		}`))
	}))
	defer srv.Close()

	adv, err := fetchAdvisory(context.Background(), srv.URL+"/", "MAL-2026-3199")
	if err != nil {
		t.Fatal(err)
	}
	if adv.ID != "MAL-2026-3199" {
		t.Errorf("expected MAL-2026-3199, got %s", adv.ID)
	}
	if adv.Summary != "Malicious package" {
		t.Errorf("unexpected summary: %s", adv.Summary)
	}
	if len(adv.Affected) != 1 || adv.Affected[0].Package.Name != "blackbeards-navigator" {
		t.Errorf("unexpected affected: %+v", adv.Affected)
	}
}

func TestNormalizeEcosystem(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"npm", "npm"},
		{"NPM", "npm"},
		{"pypi", "PyPI"},
		{"pip", "PyPI"},
		{"go", "Go"},
		{"golang", "Go"},
		{"rubygems", "RubyGems"},
		{"gem", "RubyGems"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		got := normalizeEcosystem(tt.input)
		if got != tt.want {
			t.Errorf("normalizeEcosystem(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFilterByEcosystem(t *testing.T) {
	entries := []MALEntry{
		{ID: "MAL-1", Ecosystem: "npm"},
		{ID: "MAL-2", Ecosystem: "PyPI"},
		{ID: "MAL-3", Ecosystem: "npm"},
		{ID: "MAL-4", Ecosystem: "Go"},
	}

	filtered := filterByEcosystem(entries, []string{"npm"})
	if len(filtered) != 2 {
		t.Fatalf("expected 2, got %d", len(filtered))
	}

	filtered = filterByEcosystem(entries, []string{"pypi", "go"})
	if len(filtered) != 2 {
		t.Fatalf("expected 2, got %d", len(filtered))
	}

	filtered = filterByEcosystem(entries, nil)
	if len(filtered) != 4 {
		t.Fatalf("expected 4 (no filter), got %d", len(filtered))
	}
}

func TestStatePersistence(t *testing.T) {
	path := t.TempDir() + "/state.json"

	// No file yet — should return zero time
	ts := loadState(path)
	if !ts.IsZero() {
		t.Fatalf("expected zero time, got %v", ts)
	}

	// Save and reload
	now := time.Date(2026, 4, 30, 15, 37, 33, 0, time.UTC)
	saveState(path, now)

	ts = loadState(path)
	if !ts.Equal(now) {
		t.Fatalf("expected %v, got %v", now, ts)
	}
}

func TestStatePersistence_CorruptFile(t *testing.T) {
	path := t.TempDir() + "/state.json"
	os.WriteFile(path, []byte("not json"), 0644)

	ts := loadState(path)
	if !ts.IsZero() {
		t.Fatalf("expected zero time for corrupt file, got %v", ts)
	}
}

func TestRenderAdvisory_Plain(t *testing.T) {
	adv := Advisory{
		ID:       "MAL-2025-49286",
		Summary:  "Malicious package stealing tokens",
		Modified: time.Date(2025, 10, 31, 0, 0, 0, 0, time.UTC),
		Affected: []AffectedPackage{
			{
				Package:  osvPackage{Ecosystem: "npm", Name: "gunpowder-ghost"},
				Versions: []string{"209.0.0", "211.0.0", "212.0.0"},
			},
		},
	}

	var buf bytes.Buffer
	renderAdvisory(&buf, adv, true)
	out := buf.String()

	if !strings.Contains(out, "MAL-2025-49286") {
		t.Error("missing MAL ID")
	}
	if !strings.Contains(out, "npm") {
		t.Error("missing ecosystem")
	}
	if !strings.Contains(out, "gunpowder-ghost") {
		t.Error("missing package name")
	}
	if !strings.Contains(out, "Malicious package stealing tokens") {
		t.Error("missing summary")
	}
	if !strings.Contains(out, "osv.dev/vulnerability/MAL-2025-49286") {
		t.Error("missing osv.dev link")
	}
}

func TestRenderAdvisory_MultipleAffected(t *testing.T) {
	adv := Advisory{
		ID:      "MAL-2026-100",
		Summary: "Bad package",
		Affected: []AffectedPackage{
			{Package: osvPackage{Ecosystem: "npm", Name: "pkg-a"}, Versions: []string{"1.0.0"}},
			{Package: osvPackage{Ecosystem: "npm", Name: "pkg-b"}, Versions: []string{"2.0.0"}},
		},
	}

	var buf bytes.Buffer
	renderAdvisory(&buf, adv, true)
	out := buf.String()

	if !strings.Contains(out, "pkg-a") || !strings.Contains(out, "pkg-b") {
		t.Error("should render all affected packages")
	}
}
