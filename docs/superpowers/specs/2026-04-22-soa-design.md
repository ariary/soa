# soa — Design Specification

**Date:** 2026-04-22
**Status:** Draft

## 1. Overview

soa is a CLI security wrapper that acts as a local intercepting proxy for package managers. Instead of checking manifests, it intercepts actual binary/source downloads at the protocol level (e.g., GOPROXY) to enforce security policies on both top-level and transitive dependencies.

**v1 scope:** Go ecosystem only. Designed from day one for easy extension to npm, pip, etc.

**Binary name:** `soa`
**Language:** Go
**CLI framework:** `github.com/ariary/quicli`

## 2. CLI Dispatch

```
soa serve [--port]       → starts the reference check server
soa <anything...>        → starts proxy, injects env vars, exec's <anything> as subprocess
soa --go=false <cmd>     → disable Go interception for this invocation
```

`soa` never hardcodes which command to run. `soa gogo test`, `soa make build`, `soa ./scripts/install.sh` all work. The proxy intercepts at the network layer via environment variable injection.

`soa` propagates the subprocess exit code. If the subprocess exits 1, `soa` exits 1. If a package is blocked and the toolchain fails as a result, the toolchain's exit code flows through.

## 3. Project Structure

```
soa/
├── cmd/
│   └── soa/              # single entry point (quicli-based)
├── internal/
│   ├── proxy/            # core HTTP intercepting proxy
│   ├── manager/          # Manager interface + GolangManager
│   ├── check/            # PolicyClient — HTTP client to check endpoint
│   ├── server/           # 'soa serve' reference check server
│   ├── ui/               # ANSI spinner (no external deps)
│   └── config/           # config file + env var loading
├── pkg/
│   └── checkapi/         # shared request/response types (public contract)
├── configs/
│   └── config.example.yaml
└── README.md
```

- `internal/` is private to the soa module.
- `pkg/checkapi/` is public so anyone building a custom check server can import the contract types.

## 4. Manager Interface

```go
type Manager interface {
    Name() string
    Detect(env []string) (upstream string, active bool)
    InjectEnv(env []string, proxyAddr string) []string
    Match(r *http.Request) bool
    Parse(r *http.Request) (PackageRequest, error)
    UpstreamURL(upstream string, r *http.Request) string
}

type PackageRequest struct {
    Module  string // "github.com/foo/bar"
    Version string // "v1.2.3"
    Type    string // "info", "mod", "zip"
}
```

### Manager Lifecycle

1. **Detect()** — inspects current env to find the upstream registry. For Go: reads `GOPROXY` from env, falls back to `go env GOPROXY`, defaults to `https://proxy.golang.org,direct`.
2. **InjectEnv()** — overrides the registry var to point at soa's local proxy. For Go: sets `GOPROXY=http://localhost:<port>`, `GONOSUMDB=*`, `GONOSUMCHECK=*`.
3. **Match()** / **Parse()** — on each incoming proxy request, identifies if it belongs to this manager and extracts package info.
4. **UpstreamURL()** — builds the real upstream URL to forward to.

### GolangManager

- Handles `/@v/<version>.<ext>` path patterns (`.info`, `.mod`, `.zip`).
- Only `.zip` requests trigger a policy check. `.info` and `.mod` pass through freely.
- URL parsing: `GET /github.com/foo/bar/@v/v1.2.3.zip` → `{Module: "github.com/foo/bar", Version: "v1.2.3", Type: "zip"}`.

### Ecosystem Auto-Detection

Managers are auto-discovered from the environment, not guessed from the binary name. soa inspects env vars for each known ecosystem and activates matching managers. Disabled via `--<ecosystem>=false` flags.

## 5. Data Flow

```
soa <cmd> [args...]
  → config.Load()
  → for each Manager: Detect(env) → active if upstream found
  → active managers call InjectEnv() (GOPROXY → localhost, GONOSUMDB=*)
  → proxy.Start(port)
  → exec.Command(<cmd>, args...) with modified env, stdout/stderr piped through
  │
  │   [toolchain requests /@v/foo@v1.2.3.zip]
  │       proxy receives request
  │       matching Manager.Parse(url) → {module, version, type: "zip"}
  │       type == .zip → PolicyClient.Check(module, version)
  │           ui.Spinner.Start("scanning foo@v1.2.3")
  │           POST <check_url>/check {module, version}
  │           ├── "allowed"    → stream zip from upstream; spinner shows ✓
  │           ├── "blocked"    → return 403; spinner shows ✗
  │           └── "processing" → poll GET /check/<id>; update spinner progress
  │
  │   [toolchain requests .info or .mod]
  │       forward upstream transparently (no check)
  │
  │   [unrecognized request]
  │       forward upstream transparently
  │
  └── proxy.Stop() when subprocess exits
```

## 6. Check Server & Policy Client Contract

### Shared Types (`pkg/checkapi/`)

```go
const (
    StatusAllowed    = "allowed"
    StatusBlocked    = "blocked"
    StatusProcessing = "processing"
)

type CheckRequest struct {
    Module  string `json:"module"`
    Version string `json:"version"`
    Hash    string `json:"hash,omitempty"`
}

type CheckResponse struct {
    Status   string  `json:"status"`
    Reason   string  `json:"reason,omitempty"`
    Progress float64 `json:"progress,omitempty"` // 0.0–1.0
    ID       string  `json:"id,omitempty"`
}
```

### Policy Client (`internal/check/`)

- Stateless HTTP client.
- `Check(ctx, CheckRequest) → (CheckResponse, error)`.
- Sends `POST <check_url>/check` with JSON body.
- If response is `processing`, polls `GET <check_url>/check/<id>` at `poll_interval`.
- Timeout from config (default: 30s).
- **Fail-closed:** if check server is unreachable, block the package.

### Reference Check Server (`internal/server/`, run via `soa serve`)

Endpoint: `POST /check`

Logic:
1. Lookup `{module, version}` in approved cache → if found, return `{status: "allowed"}`.
2. Query `proxy.golang.org/<module>/@v/<version>.info` → parse `Time` field.
3. If published < `max_age_days` (default: 7) ago → `{status: "blocked", reason: "published N days ago"}`.
4. Otherwise → `{status: "allowed"}`, add to cache.

Endpoint: `GET /check/<id>`

Returns current status and progress for async checks. v1 checks are synchronous (age check is fast), but the contract supports deferred checks for future LLM analysis.

Cache is persisted to disk (`~/.config/soa/approved.json`) — survives restarts.

## 7. Configuration

### Config File: `~/.config/soa/config.yaml`

```yaml
check_url: "http://localhost:9090"

proxy:
  port: 8080

poll_interval: "500ms"
check_timeout: "30s"

server:
  port: 9090
  cache_path: "~/.config/soa/approved.json"
  max_age_days: 7
```

### Environment Variable Overrides

| Config key | Env var | Default |
|---|---|---|
| `check_url` | `SOA_CHECK_URL` | `http://localhost:9090` |
| `proxy.port` | `SOA_PROXY_PORT` | `8080` |
| `check_timeout` | `SOA_CHECK_TIMEOUT` | `30s` |
| `poll_interval` | `SOA_POLL_INTERVAL` | `500ms` |
| `server.port` | `SOA_SERVER_PORT` | `9090` |
| `server.cache_path` | `SOA_SERVER_CACHE_PATH` | `~/.config/soa/approved.json` |
| `server.max_age_days` | `SOA_SERVER_MAX_AGE_DAYS` | `7` |

**Precedence:** env var > config file > defaults.

### CLI Flags

- `--go=false` / `--npm=false` — disable ecosystem interception per-invocation.
- `soa serve --port <N>` — override serve port.

Flags do not duplicate config. They exist only for per-invocation overrides.

## 8. UI / Spinner

ANSI spinner on stderr, no external dependencies. Raw escape sequences.

```
[soa] ⠋ scanning github.com/foo/bar@v1.2.3
[soa] ⠙ scanning github.com/foo/bar@v1.2.3 [████░░░░ 45%]
[soa] ✓ github.com/foo/bar@v1.2.3 allowed
[soa] ✗ github.com/foo/bar@v1.2.3 blocked: published 2 days ago
```

- Writes to stderr only — never touches stdout.
- Braille spinner chars (`⠋⠙⠹⠸⠼⠴⠦⠧`), cycling.
- Progress bar shown when check server returns `progress` values.
- Multiple concurrent checks → one spinner line per package, stacked.
- Non-TTY fallback → simple static log lines, no ANSI.
- If subprocess writes to stderr simultaneously, spinner pauses redraw to avoid garbling.
- Uses `\r` + ANSI clear-line (`\033[2K`) for in-place updates.

## 9. Error Handling

Fail-closed philosophy.

| Scenario | Behavior |
|---|---|
| Check server unreachable | Block all `.zip` downloads, print error |
| Check server returns invalid JSON | Block, log raw response |
| Check server timeout | Block, show timeout duration |
| Upstream Go proxy unreachable | Let `go` handle it — return upstream error as-is |
| No config file found | Run with defaults |
| Invalid config file | Exit immediately with clear parse error |
| No ecosystems detected | Warn on stderr, run subprocess as transparent passthrough |
| `soa serve` cache file corrupted | Log warning, start with empty cache |

## 10. README Structure

```
# 🛃 soa

Your packages go through customs now.

## The gist
(2-3 sentences)

## Show me
(3 commands: start serve, wrap a go get, watch it work)

## Get it
(go install one-liner)

## Under the hood
(short diagram)

## Knobs
(config + env vars + flags table)

## FAQ
```

## 11. Future Extensions (Out of v1 Scope)

- **NPM Manager** — intercept `NPM_CONFIG_REGISTRY`, prune unsafe versions from JSON metadata.
- **pip Manager** — intercept `PIP_INDEX_URL`.
- **LLM analysis** — `soa serve` sends archive to LLM for behavioral analysis; uses `processing` + progress contract.
- **CVE checking** — query vulnerability databases as an additional check step.
- **`soa config` subcommand** — interactive config management.
