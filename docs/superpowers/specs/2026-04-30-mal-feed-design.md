# MAL Advisory Feed (`soa feed`)

## Problem

soa checks packages at download time using rules (MaxAge, MinVersions, LLM Analysis), but has no awareness of known malicious packages catalogued by the security community. The OpenSSF Malicious Packages database (osv.dev MAL-* advisories) tracks thousands of confirmed malicious packages across npm, PyPI, Go, and RubyGems -- the same ecosystems soa protects.

Users need a way to monitor this feed in real-time to stay informed about new supply chain threats.

## Solution

A new `soa feed` subcommand that polls osv.dev's data export for new MAL-* advisories and prints alerts to the terminal.

## Architecture

```
soa feed [--interval 5m] [--ecosystem npm,pypi]
  |
  +-- Poll loop (configurable interval, default 5m)
  |   +-- HTTP Range GET first ~50KB of modified_id.csv from GCS bucket
  |   +-- Filter lines containing /MAL- (malicious package advisories)
  |   +-- Skip entries older than last_seen timestamp
  |   +-- Fetch full advisory from osv.dev GET /v1/vulns/{id}
  |   +-- Filter by ecosystem if specified
  |   +-- Print formatted alert to terminal
  |
  +-- State file (~/.config/soa/feed-state.json)
      +-- Persists last_seen timestamp across restarts
```

### Data source: osv.dev modified_id.csv

osv.dev publishes a `modified_id.csv` file at:
`https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv`

Format (reverse chronological, newest first):
```
2026-04-30T15:37:33.526586Z,npm/MAL-2025-49286
2026-04-30T15:32:51.46441Z,npm/MAL-2026-3199
2026-04-30T15:31:38.253098Z,MinimOS/MINI-9xh5-38jf-44x8
...
```

The file is ~42MB but sorted with newest entries first. Using HTTP Range requests (`Range: bytes=0-51200`) we fetch only the first ~50KB, which covers several hours of entries -- more than enough for a 5-minute polling interval.

MAL entries are identifiable by `/MAL-` in the second column. The first column before the `/` is the ecosystem (npm, PyPI, Go, RubyGems, etc.).

### Propagation delay

Measured empirically: osv.dev updates ~13-18 minutes after a commit lands in the ossf/malicious-packages GitHub repo. This matches osv.dev's stated SLO of "within 15 minutes, 99.5% of the time." For a 5-minute poll interval, new MAL entries appear within 15-20 minutes of discovery.

### Data flow

1. `GET modified_id.csv` with `Range: bytes=0-51200` header
2. Parse CSV lines, filter for `/MAL-` entries
3. Parse timestamp, skip entries older than `last_seen`
4. Extract MAL ID from second column (e.g. `npm/MAL-2025-49286` -> `MAL-2025-49286`)
5. For each new ID: `GET https://api.osv.dev/v1/vulns/{id}` -> full advisory
6. Filter by configured ecosystems if any
7. Render to terminal
8. Update `last_seen` to most recent entry timestamp, persist to state file

## Terminal output format

```
[soa] feed started (polling every 5m)
---
[MAL-2025-49286] npm / gunpowder-ghost@209.0.0, 211.0.0, ...
  Communicates with domain associated with malicious activity
  2025-10-31  https://osv.dev/vulnerability/MAL-2025-49286
---
[MAL-2026-3199] npm / blackbeards-navigator@207.0.0, 208.0.0, ...
  Executes commands associated with malicious behavior
  2026-04-30  https://osv.dev/vulnerability/MAL-2026-3199
---
```

TTY mode: colored output (red for MAL ID, yellow for ecosystem, cyan for package name).
Non-TTY mode: plain text, same structure.

## Components

### 1. Feed package (`internal/feed/feed.go`)

Single file containing all feed logic:

```go
// Advisory types matching osv.dev response
type Advisory struct {
    ID       string
    Summary  string
    Modified time.Time
    Affected []AffectedPackage
}

type AffectedPackage struct {
    Ecosystem string
    Name      string
    Versions  []string
}

// FetchRecentMALIDs fetches the first ~50KB of modified_id.csv,
// returns MAL entries newer than since.
func FetchRecentMALIDs(ctx context.Context, since time.Time) ([]MALEntry, error)

// MALEntry is a parsed line from modified_id.csv.
type MALEntry struct {
    Modified  time.Time
    Ecosystem string // "npm", "PyPI", etc.
    ID        string // "MAL-2025-49286"
}

// FetchAdvisory fetches full advisory from osv.dev.
// GET https://api.osv.dev/v1/vulns/{id}
func FetchAdvisory(ctx context.Context, id string) (Advisory, error)

// Config holds feed configuration.
type Config struct {
    Interval   time.Duration // default 5m
    Ecosystems []string      // filter, empty = all
    StatePath  string        // ~/.config/soa/feed-state.json
}

// Run starts the poll loop. Blocks until ctx is cancelled.
func Run(ctx context.Context, cfg Config, w io.Writer, plain bool) error
```

State persistence: load/save `{"last_seen": "2026-04-30T15:37:33Z"}` JSON file.

Rendering: inline functions for TTY and plain text output. Uses ANSI escape codes consistent with existing `internal/ui/spinner.go` patterns.

### 2. CLI wiring (`cmd/soa/main.go`)

New subcommand:

```go
{Name: "feed", Description: "Live feed of malicious package advisories from osv.dev", Function: feedCmd}
```

Flags (shared with feed subcommand):
- `interval` (string, default `"5m"`): polling interval
- `ecosystem` (string, default `""`): comma-separated ecosystem filter

`feedCmd` creates a `feed.Config`, determines TTY mode, calls `feed.Run()`.

## Ecosystem normalization

The CSV uses osv.dev ecosystem names. The `--ecosystem` filter accepts case-insensitive input:

| User input    | CSV ecosystem |
|---------------|---------------|
| npm           | npm           |
| pypi, pip     | PyPI          |
| go, golang    | Go            |
| rubygems, gem | RubyGems      |

## Error handling

- HTTP Range request fails: fall back to fetching first 51200 bytes without Range header, or log warning and retry next interval
- osv.dev advisory fetch fails: log warning per-advisory, continue with others
- Network errors: do not update last_seen (retry same window next poll)
- SIGINT/SIGTERM: save state before exit
- CSV parse errors: skip malformed lines, continue

## State persistence

- File: `~/.config/soa/feed-state.json`
- Format: `{"last_seen": "2026-04-30T15:37:33.526586Z"}`
- First run (no state file): look back 24 hours
- Updated after each successful poll to the most recent MAL entry timestamp

## Rate limits

- osv.dev GCS bucket: no rate limits, public read access
- osv.dev API: no rate limits
- Bandwidth: ~50KB per poll (Range request) + ~2-5KB per advisory detail

## Files to create/modify

| Action | File |
|--------|------|
| Create | `internal/feed/feed.go` |
| Modify | `cmd/soa/main.go` |

## Testing

- `go build ./...` compiles
- `soa feed --interval 1m` starts and prints recent MAL advisories
- `soa feed --ecosystem npm` filters to npm only
- Ctrl+C stops cleanly, state file is saved
- Re-running picks up from last_seen state (no duplicates)
- Works without any token or external setup
