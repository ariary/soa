package feed

import (
	"bytes"
	"context"
	"encoding/json"
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
	renderAdvisory(&buf, adv, RenderConfig{Plain: true})
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
	renderAdvisory(&buf, adv, RenderConfig{Plain: true})
	out := buf.String()

	if !strings.Contains(out, "pkg-a") || !strings.Contains(out, "pkg-b") {
		t.Error("should render all affected packages")
	}
}

func TestRun_SinglePoll(t *testing.T) {
	csvData := `2026-04-30T15:37:33.526586Z,npm/MAL-2025-49286
2026-04-30T15:32:51.46441Z,npm/MAL-2026-3199
2026-04-30T14:00:00Z,PyPI/GHSA-other
`
	advisory1 := `{"id":"MAL-2025-49286","summary":"Worm","modified":"2026-04-30T15:37:33Z","affected":[{"package":{"ecosystem":"npm","name":"gunpowder-ghost"},"versions":["1.0.0"]}]}`
	advisory2 := `{"id":"MAL-2026-3199","summary":"Bad pkg","modified":"2026-04-30T15:32:51Z","affected":[{"package":{"ecosystem":"npm","name":"blackbeards-navigator"},"versions":["2.0.0"]}]}`

	mux := http.NewServeMux()
	mux.HandleFunc("/csv", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(csvData))
	})
	mux.HandleFunc("/MAL-2025-49286", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(advisory1))
	})
	mux.HandleFunc("/MAL-2026-3199", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(advisory2))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	statePath := t.TempDir() + "/state.json"
	var buf bytes.Buffer

	cfg := Config{
		Interval:   0, // single poll
		Ecosystems: nil,
		StatePath:  statePath,
		EnableOSV:  true,
		csvURL:     srv.URL + "/csv",
		osvAPIBase: srv.URL + "/",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := Run(ctx, cfg, &buf, true)
	if err != nil && err != context.Canceled {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.Contains(out, "MAL-2025-49286") {
		t.Error("missing MAL-2025-49286 in output")
	}
	if !strings.Contains(out, "MAL-2026-3199") {
		t.Error("missing MAL-2026-3199 in output")
	}

	// State should be persisted
	ts := loadState(statePath)
	if ts.IsZero() {
		t.Error("expected state to be saved")
	}
}

func TestRun_OSVDisabled(t *testing.T) {
	csvHit := false
	mux := http.NewServeMux()
	mux.HandleFunc("/csv", func(w http.ResponseWriter, r *http.Request) {
		csvHit = true
		w.Write([]byte(`2026-04-30T15:37:33Z,npm/MAL-2025-1`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var buf bytes.Buffer
	cfg := Config{
		Interval:  0,
		StatePath: t.TempDir() + "/state.json",
		EnableOSV: false,
		csvURL:    srv.URL + "/csv",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	Run(ctx, cfg, &buf, true)
	if csvHit {
		t.Error("CSV endpoint should not be called when EnableOSV is false")
	}
	if buf.Len() != 0 {
		t.Errorf("expected no output, got %q", buf.String())
	}
}

func TestRun_GHSAOnly(t *testing.T) {
	csvHit := false
	mux := http.NewServeMux()
	mux.HandleFunc("/csv", func(w http.ResponseWriter, r *http.Request) {
		csvHit = true
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"securityAdvisories":{"nodes":[{
			"ghsaId":"GHSA-test-0001",
			"summary":"Malware npm pkg",
			"publishedAt":"2026-04-30T16:00:00Z",
			"vulnerabilities":{"nodes":[{"package":{"ecosystem":"NPM","name":"evil-pkg"},"vulnerableVersionRange":"= 1.0.0"}]}
		}],"pageInfo":{"hasNextPage":false,"endCursor":""}}}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var buf bytes.Buffer
	cfg := Config{
		Interval:     0,
		StatePath:    t.TempDir() + "/state.json",
		EnableOSV:    false,
		EnableGHSA:   true,
		GithubToken:  "test-token",
		ghGraphqlURL: srv.URL + "/graphql",
		csvURL:       srv.URL + "/csv",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	Run(ctx, cfg, &buf, true)
	if csvHit {
		t.Error("CSV endpoint should not be called when EnableOSV is false")
	}
	if !strings.Contains(buf.String(), "GHSA-test-0001") {
		t.Errorf("expected GHSA advisory in output, got %q", buf.String())
	}
}

func TestRun_GHSADisabledWithToken(t *testing.T) {
	ghsaHit := false
	mux := http.NewServeMux()
	mux.HandleFunc("/csv", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`2026-04-30T15:37:33Z,npm/MAL-2025-1`))
	})
	mux.HandleFunc("/MAL-2025-1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":"MAL-2025-1","summary":"Bad","modified":"2026-04-30T15:37:33Z","affected":[{"package":{"ecosystem":"npm","name":"bad-pkg"},"versions":["1.0.0"]}]}`))
	})
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		ghsaHit = true
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var buf bytes.Buffer
	cfg := Config{
		Interval:     0,
		StatePath:    t.TempDir() + "/state.json",
		EnableOSV:    true,
		EnableGHSA:   false,
		GithubToken:  "test-token",
		ghGraphqlURL: srv.URL + "/graphql",
		csvURL:       srv.URL + "/csv",
		osvAPIBase:   srv.URL + "/",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	Run(ctx, cfg, &buf, true)
	if ghsaHit {
		t.Error("GHSA endpoint should not be called when EnableGHSA is false")
	}
	if !strings.Contains(buf.String(), "MAL-2025-1") {
		t.Errorf("expected MAL advisory in output, got %q", buf.String())
	}
}

func TestRun_SinceOverridesDefault(t *testing.T) {
	// CSV has entries at two timestamps; set Since to only catch the newer one
	csvData := `2026-04-30T16:00:00Z,npm/MAL-2026-NEW
2026-04-30T10:00:00Z,npm/MAL-2026-OLD
`
	mux := http.NewServeMux()
	mux.HandleFunc("/csv", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(csvData))
	})
	mux.HandleFunc("/MAL-2026-NEW", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":"MAL-2026-NEW","summary":"New","modified":"2026-04-30T16:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"new-pkg"},"versions":["1.0.0"]}]}`))
	})
	mux.HandleFunc("/MAL-2026-OLD", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":"MAL-2026-OLD","summary":"Old","modified":"2026-04-30T10:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"old-pkg"},"versions":["1.0.0"]}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var buf bytes.Buffer
	cfg := Config{
		Interval:   0,
		StatePath:  t.TempDir() + "/state.json",
		EnableOSV:  true,
		Since:      time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC), // only entries after noon
		csvURL:     srv.URL + "/csv",
		osvAPIBase: srv.URL + "/",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	Run(ctx, cfg, &buf, true)
	out := buf.String()
	if !strings.Contains(out, "MAL-2026-NEW") {
		t.Error("expected MAL-2026-NEW in output")
	}
	if strings.Contains(out, "MAL-2026-OLD") {
		t.Error("MAL-2026-OLD should be filtered out by Since")
	}
}

func TestRun_StateFileOverridesSince(t *testing.T) {
	// State file has a newer timestamp than Since — state should win
	csvData := `2026-04-30T18:00:00Z,npm/MAL-2026-LATEST
2026-04-30T14:00:00Z,npm/MAL-2026-MID
`
	mux := http.NewServeMux()
	mux.HandleFunc("/csv", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(csvData))
	})
	mux.HandleFunc("/MAL-2026-LATEST", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":"MAL-2026-LATEST","summary":"Latest","modified":"2026-04-30T18:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"latest-pkg"},"versions":["1.0.0"]}]}`))
	})
	mux.HandleFunc("/MAL-2026-MID", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":"MAL-2026-MID","summary":"Mid","modified":"2026-04-30T14:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"mid-pkg"},"versions":["1.0.0"]}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	statePath := t.TempDir() + "/state.json"
	// Pre-save state at 16:00 — should ignore Since and only show entries after 16:00
	saveState(statePath, time.Date(2026, 4, 30, 16, 0, 0, 0, time.UTC))

	var buf bytes.Buffer
	cfg := Config{
		Interval:   0,
		StatePath:  statePath,
		EnableOSV:  true,
		Since:      time.Date(2026, 4, 30, 10, 0, 0, 0, time.UTC), // far back, but state overrides
		csvURL:     srv.URL + "/csv",
		osvAPIBase: srv.URL + "/",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	Run(ctx, cfg, &buf, true)
	out := buf.String()
	if !strings.Contains(out, "MAL-2026-LATEST") {
		t.Error("expected MAL-2026-LATEST in output")
	}
	if strings.Contains(out, "MAL-2026-MID") {
		t.Error("MAL-2026-MID should be filtered out — state file is newer than its timestamp")
	}
}

func TestRun_SkipsWithdrawnAdvisories(t *testing.T) {
	withdrawn := time.Date(2026, 4, 30, 18, 0, 0, 0, time.UTC)
	adv := Advisory{
		ID:        "MAL-2026-WITHDRAWN",
		Summary:   "Retracted",
		Modified:  time.Date(2026, 4, 30, 15, 37, 33, 0, time.UTC),
		Withdrawn: &withdrawn,
		Affected: []AffectedPackage{
			{Package: osvPackage{Ecosystem: "npm", Name: "retracted-pkg"}, Versions: []string{"1.0.0"}},
		},
	}
	advJSON, _ := json.Marshal(adv)

	mux := http.NewServeMux()
	mux.HandleFunc("/csv", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("2026-04-30T15:37:33Z,npm/MAL-2026-WITHDRAWN\n"))
	})
	mux.HandleFunc("/MAL-2026-WITHDRAWN", func(w http.ResponseWriter, r *http.Request) {
		w.Write(advJSON)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var buf bytes.Buffer
	cfg := Config{
		Interval:   0,
		StatePath:  t.TempDir() + "/state.json",
		EnableOSV:  true,
		csvURL:     srv.URL + "/csv",
		osvAPIBase: srv.URL + "/",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	Run(ctx, cfg, &buf, true)
	if strings.Contains(buf.String(), "MAL-2026-WITHDRAWN") {
		t.Error("withdrawn advisory should not appear in output")
	}
}

func TestDedup_UsesAliases(t *testing.T) {
	malAdvs := []Advisory{
		{
			ID:      "MAL-2026-100",
			Aliases: []string{"GHSA-dup1-dup1-dup1"},
			Affected: []AffectedPackage{
				{Package: osvPackage{Ecosystem: "npm", Name: "pkg-a"}},
			},
		},
	}
	ghsaAdvs := []Advisory{
		{
			// Should be deduped by alias match
			ID: "GHSA-dup1-dup1-dup1",
			Affected: []AffectedPackage{
				{Package: osvPackage{Ecosystem: "npm", Name: "pkg-a-renamed"}},
			},
		},
		{
			// Should survive — no alias or package match
			ID: "GHSA-uniq-uniq-uniq",
			Affected: []AffectedPackage{
				{Package: osvPackage{Ecosystem: "npm", Name: "pkg-b"}},
			},
		},
	}

	result := dedup(ghsaAdvs, malAdvs)
	if len(result) != 1 {
		t.Fatalf("expected 1 unique advisory, got %d", len(result))
	}
	if result[0].ID != "GHSA-uniq-uniq-uniq" {
		t.Errorf("expected GHSA-uniq-uniq-uniq, got %s", result[0].ID)
	}
}

func TestFormatRanges(t *testing.T) {
	tests := []struct {
		name   string
		ranges []VersionRange
		want   string
	}{
		{
			name:   "empty",
			ranges: nil,
			want:   "",
		},
		{
			name: "all versions",
			ranges: []VersionRange{
				{Type: "ECOSYSTEM", Events: []RangeEvent{{Introduced: "0"}}},
			},
			want: "all versions",
		},
		{
			name: "range with fix",
			ranges: []VersionRange{
				{Type: "SEMVER", Events: []RangeEvent{
					{Introduced: "1.0.0"},
					{Fixed: "2.0.0"},
				}},
			},
			want: ">= 1.0.0, < 2.0.0",
		},
		{
			name: "introduced only",
			ranges: []VersionRange{
				{Type: "ECOSYSTEM", Events: []RangeEvent{{Introduced: "3.0.0"}}},
			},
			want: ">= 3.0.0",
		},
		{
			name: "fixed only",
			ranges: []VersionRange{
				{Type: "ECOSYSTEM", Events: []RangeEvent{{Fixed: "5.0.0"}}},
			},
			want: "< 5.0.0",
		},
		{
			name: "last_affected treated as upper bound",
			ranges: []VersionRange{
				{Type: "ECOSYSTEM", Events: []RangeEvent{
					{Introduced: "1.0.0"},
					{LastAffected: "1.9.9"},
				}},
			},
			want: ">= 1.0.0, < 1.9.9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatRanges(tt.ranges)
			if got != tt.want {
				t.Errorf("formatRanges() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseGHSARange(t *testing.T) {
	tests := []struct {
		input string
		want  string // formatted via formatRanges
	}{
		{">= 0", "all versions"},
		{">= 1.0.0, < 2.0.0", ">= 1.0.0, < 2.0.0"},
		{"< 3.0.0", "< 3.0.0"},
		{">= 1.0.0", ">= 1.0.0"},
	}
	for _, tt := range tests {
		r := parseGHSARange(tt.input)
		if r.Type != "ECOSYSTEM" {
			t.Errorf("parseGHSARange(%q).Type = %q, want ECOSYSTEM", tt.input, r.Type)
		}
		got := formatRanges([]VersionRange{r})
		if got != tt.want {
			t.Errorf("parseGHSARange(%q) formatted = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRenderAdvisory_WithRanges(t *testing.T) {
	adv := Advisory{
		ID:      "MAL-2026-200",
		Summary: "Malware with ranges",
		Modified: time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC),
		Affected: []AffectedPackage{
			{
				Package:  osvPackage{Ecosystem: "npm", Name: "evil-ranges"},
				Versions: []string{"1.0.0", "2.0.0"},
				Ranges:   []VersionRange{{Type: "ECOSYSTEM", Events: []RangeEvent{{Introduced: "0"}}}},
			},
		},
	}

	var buf bytes.Buffer
	renderAdvisory(&buf, adv, RenderConfig{Plain: true})
	out := buf.String()

	if !strings.Contains(out, "evil-ranges@1.0.0, 2.0.0 (all versions)") {
		t.Errorf("expected versions + range info, got:\n%s", out)
	}
}

func TestRenderAdvisory_RangesOnly(t *testing.T) {
	adv := Advisory{
		ID:      "GHSA-range-only",
		Summary: "Range only advisory",
		Modified: time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC),
		Affected: []AffectedPackage{
			{
				Package: osvPackage{Ecosystem: "npm", Name: "range-pkg"},
				Ranges:  []VersionRange{{Type: "ECOSYSTEM", Events: []RangeEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}},
			},
		},
	}

	var buf bytes.Buffer
	renderAdvisory(&buf, adv, RenderConfig{Plain: true})
	out := buf.String()

	if !strings.Contains(out, "range-pkg (>= 1.0.0, < 2.0.0)") {
		t.Errorf("expected range display without @, got:\n%s", out)
	}
}

func TestRenderAdvisory_UsesPublishedDate(t *testing.T) {
	adv := Advisory{
		ID:        "MAL-2026-300",
		Summary:   "Test published date",
		Modified:  time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC),
		Published: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		Affected:  []AffectedPackage{{Package: osvPackage{Ecosystem: "npm", Name: "pkg"}}},
	}

	var buf bytes.Buffer
	renderAdvisory(&buf, adv, RenderConfig{Plain: true})
	out := buf.String()

	if !strings.Contains(out, "2026-04-01") {
		t.Error("expected published date 2026-04-01 in output")
	}
	if strings.Contains(out, "2026-05-15") {
		t.Error("should use published date, not modified date")
	}
}

func TestRenderAdvisory_FallsBackToDetails(t *testing.T) {
	adv := Advisory{
		ID:       "MAL-2026-400",
		Details:  "---\nfoo: bar\n---\nThis package exfiltrates env vars\nMore details here",
		Modified: time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC),
		Affected: []AffectedPackage{{Package: osvPackage{Ecosystem: "npm", Name: "pkg"}}},
	}

	var buf bytes.Buffer
	renderAdvisory(&buf, adv, RenderConfig{Plain: true})
	out := buf.String()

	if !strings.Contains(out, "This package exfiltrates env vars") {
		t.Errorf("expected first line of details after frontmatter, got:\n%s", out)
	}
}

func TestRenderAdvisory_UsesAdvisoryReference(t *testing.T) {
	adv := Advisory{
		ID:       "MAL-2026-500",
		Summary:  "Test refs",
		Modified: time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC),
		Affected: []AffectedPackage{{Package: osvPackage{Ecosystem: "npm", Name: "pkg"}}},
		References: []Reference{
			{Type: "PACKAGE", URL: "https://npmjs.com/package/pkg"},
			{Type: "ADVISORY", URL: "https://github.com/advisories/GHSA-xxxx"},
		},
	}

	var buf bytes.Buffer
	renderAdvisory(&buf, adv, RenderConfig{Plain: true})
	out := buf.String()

	if !strings.Contains(out, "https://github.com/advisories/GHSA-xxxx") {
		t.Errorf("expected ADVISORY reference URL, got:\n%s", out)
	}
	if strings.Contains(out, "osv.dev") {
		t.Error("should prefer ADVISORY reference over constructed osv.dev URL")
	}
}

func TestRenderAdvisory_InfoShort(t *testing.T) {
	adv := Advisory{
		ID:       "MAL-2025-49286",
		Summary:  "Should not appear",
		Modified: time.Date(2025, 10, 31, 0, 0, 0, 0, time.UTC),
		Affected: []AffectedPackage{
			{Package: osvPackage{Ecosystem: "npm", Name: "gunpowder-ghost"}, Versions: []string{"1.0.0"}},
		},
	}

	var buf bytes.Buffer
	renderAdvisory(&buf, adv, RenderConfig{Plain: true, Level: InfoShort})
	out := buf.String()

	if !strings.Contains(out, "MAL-2025-49286") {
		t.Error("missing MAL ID in short mode")
	}
	if !strings.Contains(out, "gunpowder-ghost") {
		t.Error("missing package name in short mode")
	}
	if strings.Contains(out, "Should not appear") {
		t.Error("summary should not appear in short mode")
	}
	if strings.Contains(out, "osv.dev") {
		t.Error("link should not appear in short mode")
	}
}

func TestRenderAdvisory_InfoFull(t *testing.T) {
	raw := json.RawMessage(`{
		"id": "MAL-2025-49286",
		"summary": "Malicious package",
		"modified": "2025-10-31T00:00:00Z",
		"details": "This package exfiltrates environment variables",
		"aliases": ["CVE-2025-1234"],
		"severity": [{"type": "CVSS_V3", "score": "9.8"}],
		"references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}],
		"affected": [{"package": {"ecosystem": "npm", "name": "gunpowder-ghost"}, "versions": ["1.0.0"]}]
	}`)

	adv := Advisory{
		ID:       "MAL-2025-49286",
		Summary:  "Malicious package",
		Details:  "This package exfiltrates environment variables",
		Aliases:  []string{"CVE-2025-1234"},
		Modified: time.Date(2025, 10, 31, 0, 0, 0, 0, time.UTC),
		Affected: []AffectedPackage{
			{Package: osvPackage{Ecosystem: "npm", Name: "gunpowder-ghost"}, Versions: []string{"1.0.0"}},
		},
		References: []Reference{{Type: "ADVISORY", URL: "https://example.com/advisory"}},
		Raw:        raw,
	}

	var buf bytes.Buffer
	renderAdvisory(&buf, adv, RenderConfig{Plain: true, Level: InfoFull})
	out := buf.String()

	if !strings.Contains(out, "details:") {
		t.Errorf("missing details field in full mode, got:\n%s", out)
	}
	if !strings.Contains(out, "exfiltrates environment") {
		t.Errorf("missing details content in full mode, got:\n%s", out)
	}
	if !strings.Contains(out, "aliases:") {
		t.Errorf("missing aliases field in full mode, got:\n%s", out)
	}
	if !strings.Contains(out, "CVE-2025-1234") {
		t.Errorf("missing alias value in full mode, got:\n%s", out)
	}
	if !strings.Contains(out, "references:") {
		t.Errorf("missing references field in full mode, got:\n%s", out)
	}
	if !strings.Contains(out, "https://example.com/advisory") {
		t.Errorf("missing reference URL in full mode, got:\n%s", out)
	}
}

func TestRenderAdvisory_OSVFields(t *testing.T) {
	raw := json.RawMessage(`{
		"id": "MAL-2025-49286",
		"summary": "Malicious package",
		"modified": "2025-10-31T00:00:00Z",
		"details": "Steals tokens",
		"severity": [{"type": "CVSS_V3", "score": "9.8"}],
		"credits": [{"name": "researcher1", "type": "FINDER"}],
		"affected": [{"package": {"ecosystem": "npm", "name": "gunpowder-ghost"}, "versions": ["1.0.0"]}]
	}`)

	adv := Advisory{
		ID:       "MAL-2025-49286",
		Summary:  "Malicious package",
		Modified: time.Date(2025, 10, 31, 0, 0, 0, 0, time.UTC),
		Affected: []AffectedPackage{
			{Package: osvPackage{Ecosystem: "npm", Name: "gunpowder-ghost"}, Versions: []string{"1.0.0"}},
		},
		Raw: raw,
	}

	var buf bytes.Buffer
	renderAdvisory(&buf, adv, RenderConfig{Plain: true, OSVFields: []string{"details", "severity", "credits"}})
	out := buf.String()

	if !strings.Contains(out, "details: Steals tokens") {
		t.Errorf("missing details osv-field, got:\n%s", out)
	}
	if !strings.Contains(out, "severity: CVSS_V3: 9.8") {
		t.Errorf("missing severity osv-field, got:\n%s", out)
	}
	if !strings.Contains(out, "credits: researcher1 (FINDER)") {
		t.Errorf("missing credits osv-field, got:\n%s", out)
	}
}

func TestRenderAdvisory_OSVFields_NoRaw(t *testing.T) {
	// GHSA advisories won't have Raw — osv-field should be silently skipped
	adv := Advisory{
		ID:       "GHSA-test-0001",
		Summary:  "Malware npm pkg",
		Modified: time.Date(2026, 4, 30, 16, 0, 0, 0, time.UTC),
		Affected: []AffectedPackage{
			{Package: osvPackage{Ecosystem: "npm", Name: "evil-pkg"}, Versions: []string{"1.0.0"}},
		},
	}

	var buf bytes.Buffer
	renderAdvisory(&buf, adv, RenderConfig{Plain: true, OSVFields: []string{"details", "severity"}})
	out := buf.String()

	// Should render without errors, just no extra fields
	if !strings.Contains(out, "GHSA-test-0001") {
		t.Errorf("missing advisory ID, got:\n%s", out)
	}
	if strings.Contains(out, "details:") || strings.Contains(out, "severity:") {
		t.Error("should not show osv-field when Raw is nil")
	}
}

func TestFormatOSVField(t *testing.T) {
	tests := []struct {
		field string
		raw   string
		want  string
	}{
		{"details", `"some details"`, "some details"},
		{"aliases", `["CVE-1","CVE-2"]`, "CVE-1, CVE-2"},
		{"aliases", `[]`, "[]"},
		{"severity", `[{"type":"CVSS_V3","score":"9.8"}]`, "CVSS_V3: 9.8"},
		{"credits", `[{"name":"Alice","type":"FINDER"}]`, "Alice (FINDER)"},
		{"credits", `[{"name":"Bob","type":""}]`, "Bob"},
		{"published", `"2026-04-30T15:00:00Z"`, "2026-04-30"},
		{"schema_version", `"1.6.0"`, "1.6.0"},
		{"database_specific", `{"key":"val"}`, `{"key":"val"}`},
	}
	for _, tt := range tests {
		got := formatOSVField(tt.field, json.RawMessage(tt.raw))
		if got != tt.want {
			t.Errorf("formatOSVField(%q, %s) = %q, want %q", tt.field, tt.raw, got, tt.want)
		}
	}
}

func TestExtractRawField(t *testing.T) {
	raw := json.RawMessage(`{"id":"MAL-1","details":"foo","severity":null}`)

	// Existing field
	val, ok := extractRawField(raw, "details")
	if !ok || string(val) != `"foo"` {
		t.Errorf("expected details = %q, got %q (ok=%v)", `"foo"`, string(val), ok)
	}

	// Missing field
	_, ok = extractRawField(raw, "nonexistent")
	if ok {
		t.Error("expected missing field to return false")
	}

	// Null field
	_, ok = extractRawField(raw, "severity")
	if ok {
		t.Error("expected null field to return false")
	}

	// Nil raw
	_, ok = extractRawField(nil, "id")
	if ok {
		t.Error("expected nil raw to return false")
	}
}

func TestFirstLine(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"single line", "single line"},
		{"first\nsecond\nthird", "first"},
		{"---\nfoo: bar\n---\nafter frontmatter\nmore", "after frontmatter"},
		{"---\nfoo: bar\n---\n", ""},
		{"  \n  spaced  \n", "spaced"},
	}
	for _, tt := range tests {
		got := firstLine(tt.input)
		if got != tt.want {
			t.Errorf("firstLine(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
