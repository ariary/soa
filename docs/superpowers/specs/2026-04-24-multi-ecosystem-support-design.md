# Multi-Ecosystem Package Manager Support

**Date:** 2026-04-24
**Goal:** Add npm, pip, and RubyGems interception to soa, giving polyglot projects supply-chain security coverage across all four ecosystems (Go + the three new ones).

**Approach:** Breadth-first with light server generalization. Each ecosystem gets a full Manager implementation (client-side proxy interception) plus server-side publish-time lookups and archive extraction support for analysis.

---

## 1. New Manager Implementations (client-side)

Three new files in `internal/manager/`, each implementing the existing `Manager` interface.

### NpmManager (`npm.go`)

| Method | Behavior |
|--------|----------|
| `Name()` | `"npm"` |
| `Detect(env)` | Read `npm_config_registry`, default `https://registry.npmjs.org` |
| `InjectEnv(env, proxyAddr)` | Overwrite `npm_config_registry` to proxy address |
| `Match(r)` | URL contains `/-/` (tarball) or is a package metadata request |
| `Parse(r)` | Extract name+version from `/{pkg}/-/{pkg}-{version}.tgz` (scoped: `/@{scope}/{pkg}/-/{pkg}-{version}.tgz`) |
| `UpstreamURL(upstream, r)` | Forward to registry.npmjs.org equivalent path |

Only `.tgz` downloads set `Download: true` (triggers check). Metadata requests pass through.

### PipManager (`pip.go`)

| Method | Behavior |
|--------|----------|
| `Name()` | `"pip"` |
| `Detect(env)` | Read `PIP_INDEX_URL`, default `https://pypi.org/simple/` |
| `InjectEnv(env, proxyAddr)` | Set `PIP_INDEX_URL=http://localhost:PORT/pypi/simple/` |
| `Match(r)` | Two patterns: `/pypi/simple/{pkg}/` (index) and `/pypi/packages/...` (download) |
| `Parse(r)` | Index → metadata type (passthrough); download → extract package/version |
| `UpstreamURL(upstream, r)` | Index: forward to pypi.org/simple/; Download: forward to files.pythonhosted.org |

**Special handling:** Index responses need URL rewriting. Fetch upstream HTML, rewrite absolute download links (`files.pythonhosted.org/packages/...`) to route through the proxy (`http://localhost:PORT/pypi/packages/...`). pip's simple index format is trivial HTML (`<a href="...">` links), so parsing is ~20 lines.

Only download requests (`.whl`, `.tar.gz`) set `Download: true`.

### RubyGemsManager (`rubygems.go`)

| Method | Behavior |
|--------|----------|
| `Name()` | `"rubygems"` |
| `Detect(env)` | Read `GEM_HOST`, default `https://rubygems.org` |
| `InjectEnv(env, proxyAddr)` | Overwrite `GEM_HOST` to proxy address |
| `Match(r)` | URL matches `/gems/{name}-{version}.gem` or API/spec requests |
| `Parse(r)` | Extract gem name+version from `/gems/{name}-{version}.gem` |
| `UpstreamURL(upstream, r)` | Forward to rubygems.org equivalent path |

Only `.gem` downloads set `Download: true`. Bundler support is out of scope (follow-up).

### Proxy Response Rewriting (pip special case)

The current proxy blindly forwards upstream responses (`io.Copy`). Pip's index rewriting needs to transform the response body before sending it to the client. Add an optional `ResponseRewriter` interface:

```go
type ResponseRewriter interface {
    Rewrite(body []byte, proxyAddr string) []byte
}
```

In `proxy.handle`, after getting the upstream response, check if the matched manager implements `ResponseRewriter`. If so, buffer the response body, pass it through `Rewrite`, then write the transformed body. Only `PipManager` implements this — the others use the default `forward` path unchanged.

### PackageRequest Changes

Add `Ecosystem` and `Download` fields:

```go
type PackageRequest struct {
    Ecosystem string // "go", "npm", "pip", "rubygems"
    Module    string
    Version   string
    Type      string // ecosystem-specific type
    Download  bool   // true if this is a package download (needs check)
}

func (p PackageRequest) NeedsCheck() bool { return p.Download }
```

Each manager sets `Ecosystem` and `Download` in `Parse()`. The Go manager sets `Download: true` for `Type == "zip"` (backward-compatible).

---

## 2. CheckAPI and Server Changes

### CheckRequest

Add `Ecosystem` field:

```go
type CheckRequest struct {
    Ecosystem string `json:"ecosystem"`
    Module    string `json:"module"`
    Version   string `json:"version"`
    Hash      string `json:"hash,omitempty"`
}
```

The proxy sets this from `PackageRequest.Ecosystem` when sending the check request.

### Publish Time Lookup (`internal/registry`)

New package `internal/registry` with a single function:

```go
func FetchPublishTime(ecosystem, module, version string) (time.Time, error)
```

Dispatches by ecosystem to the appropriate public registry API:

| Ecosystem | URL | JSON path |
|-----------|-----|-----------|
| go | `https://proxy.golang.org/{module}/@v/{version}.info` | `.Time` |
| npm | `https://registry.npmjs.org/{package}` | `.time[version]` |
| pip | `https://pypi.org/pypi/{package}/{version}/json` | `.urls[0].upload_time_iso_8601` |
| rubygems | `https://rubygems.org/api/v2/rubygems/{name}/versions/{version}.json` | `.created_at` |

Each is a simple HTTP GET + JSON parse. The existing `server.fetchPublishTime` is replaced by a call to this package.

### Server Upstream URLs

Replace the single `upstreamURL string` field with well-known defaults:

```go
var defaultUpstreams = map[string]string{
    "go":       "https://proxy.golang.org",
    "npm":      "https://registry.npmjs.org",
    "pip":      "https://pypi.org",
    "rubygems": "https://rubygems.org",
}
```

`NewServer` signature changes to accept `upstreams map[string]string` instead of a single string.

### AnalysisRequest

Add `Ecosystem` field so analyzers know which fetch strategy and archive format to use:

```go
type AnalysisRequest struct {
    Ecosystem string
    Module    string
    Version   string
}
```

---

## 3. Source Extractor Generalization

### New Entry Point

Replace the zip-only `ExtractFiles` with a format-aware function:

```go
func Extract(data []byte, format string, maxBytes int) ([]File, error)
```

Where `format` is `"zip"`, `"tgz"`, or `"gem"`.

| Format | Strategy |
|--------|----------|
| `zip` | Existing logic (unchanged) |
| `tgz` | `gzip.NewReader` → `tar.NewReader`, iterate entries |
| `gem` | Outer tar contains `data.tar.gz`, extract that, then treat as tgz |

Filtering (allowed extensions, skipped dirs) and tiering (0/1/2) logic is shared — extracted into helpers used by both zip and tar paths.

### Archive Format per Ecosystem

| Ecosystem | Archive format | Fetch URL pattern |
|-----------|---------------|-------------------|
| go | zip | `{upstream}/{module}/@v/{version}.zip` |
| npm | tgz | `{upstream}/{package}/-/{package}-{version}.tgz` |
| pip | tgz | Fetch URL from `{upstream}/pypi/{package}/{version}/json`, download sdist |
| rubygems | gem | `{upstream}/gems/{name}-{version}.gem` |

### Tier 0 Additions

New entry-point files per ecosystem:

- npm: `index.js`, files referenced by `postinstall` in `package.json`
- pip: `__init__.py` (alongside existing `setup.py`)
- rubygems: `lib/{name}.rb`, files in `ext/` (C extensions)

---

## 4. CLI Flags and Wiring

### New Flags

```go
{Name: "npm",      Default: true, Description: "intercept npm package downloads"},
{Name: "pip",      Default: true, Description: "intercept pip package downloads"},
{Name: "rubygems", Default: true, Description: "intercept RubyGems downloads"},
```

All default to `true`. Disable with `--npm=false`, etc.

### proxyCmd Wiring

```go
if enableNpm      { managers = append(managers, &manager.NpmManager{}) }
if enablePip      { managers = append(managers, &manager.PipManager{}) }
if enableRubyGems { managers = append(managers, &manager.RubyGemsManager{}) }
```

### serveCmd Wiring

`NewServer` receives the upstreams map. `CodeAnalyzer` and `ReleaseAnalyzer` receive it too, dispatching fetch logic by ecosystem.

### Proxy → CheckRequest Bridge

`proxy.checkPackage` now sends `Ecosystem` from the matched manager's `PackageRequest.Ecosystem` field.

---

## 5. Tests

One `_test.go` per new manager following `golang_test.go` patterns:

- `TestNpmMatch`, `TestNpmParse`, `TestNpmUpstreamURL`
- `TestPipMatch`, `TestPipParse`, `TestPipIndexRewrite`
- `TestRubyGemsMatch`, `TestRubyGemsParse`, `TestRubyGemsUpstreamURL`
- `TestExtractTarGz`, `TestExtractGem` for the new extractor paths
- `TestFetchPublishTimeNpm`, `TestFetchPublishTimePip`, `TestFetchPublishTimeRubyGems` (mock HTTP servers)
- Update integration test to cover npm (easiest to mock end-to-end)

---

## Out of Scope

- Private registry configuration (well-known public registries only for now)
- Bundler support for RubyGems (only `gem install` flow)
- Lockfile parsing (not needed — interception happens at download time)
- Ecosystem-specific analysis prompts (current prompts are language-agnostic enough)
- yarn/pnpm (follow-up — different registry protocols)
