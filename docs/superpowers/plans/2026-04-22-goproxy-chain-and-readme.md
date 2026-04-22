# GOPROXY Chain Handling & README Polish

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Handle the full GOPROXY fallback chain (`,` vs `|` separators, `direct`, `off`) so soa can actually pull dependencies in real-world setups, and polish the README to not imply the check server must run locally.

**Architecture:** Refactor `UpstreamURL` into a chain-aware method returning parsed entries. The proxy's `forward` method iterates the chain with proper fallback semantics. Inject `,direct` into the subprocess GOPROXY so private modules (not on any proxy) can still be fetched via VCS. README wording adjustments.

**Tech Stack:** Go stdlib only (no new deps).

---

## File Structure

```
Modified:
├── internal/manager/golang.go        # parse proxy chain, handle off, inject ,direct
├── internal/manager/golang_test.go    # new tests for chain parsing, off, |, direct
├── internal/proxy/proxy.go            # forward with fallback chain
├── internal/proxy/proxy_test.go       # test fallback: 404 tries next, | tries on error
├── internal/manager/manager.go        # add ProxyEntry type
└── README.md                          # wording fixes
```

---

### Task 1: Add ProxyEntry type and chain parsing to Manager

**Files:**
- Modify: `internal/manager/manager.go`
- Modify: `internal/manager/golang.go`
- Modify: `internal/manager/golang_test.go`

- [ ] **Step 1: Add new tests for proxy chain parsing in `internal/manager/golang_test.go`**

Append these tests:

```go
func TestGolangParseUpstreamChain_CommaSeparated(t *testing.T) {
	gm := &GolangManager{}
	entries := gm.ParseUpstreamChain("https://proxy1.example,https://proxy2.example,direct")
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].URL != "https://proxy1.example" || entries[0].FallbackOnNotFound != true || entries[0].FallbackOnError != false {
		t.Errorf("entry 0: %+v", entries[0])
	}
	if entries[1].URL != "https://proxy2.example" || entries[1].FallbackOnNotFound != true {
		t.Errorf("entry 1: %+v", entries[1])
	}
	if entries[2].URL != "direct" || entries[2].IsDirect != true {
		t.Errorf("entry 2: %+v", entries[2])
	}
}

func TestGolangParseUpstreamChain_PipeSeparated(t *testing.T) {
	gm := &GolangManager{}
	entries := gm.ParseUpstreamChain("https://proxy1.example|https://proxy2.example")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].FallbackOnError != true {
		t.Errorf("pipe-separated should fallback on any error: %+v", entries[0])
	}
}

func TestGolangParseUpstreamChain_Off(t *testing.T) {
	gm := &GolangManager{}
	entries := gm.ParseUpstreamChain("off")
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if !entries[0].IsOff {
		t.Error("expected off entry")
	}
}

func TestGolangParseUpstreamChain_Mixed(t *testing.T) {
	gm := &GolangManager{}
	entries := gm.ParseUpstreamChain("https://proxy1.example|https://proxy2.example,direct")
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// proxy1 | proxy2 means proxy1 falls back on any error
	if !entries[0].FallbackOnError {
		t.Errorf("entry 0 should fallback on error (pipe): %+v", entries[0])
	}
	// proxy2 , direct means proxy2 falls back on 404/410 only
	if entries[1].FallbackOnError || !entries[1].FallbackOnNotFound {
		t.Errorf("entry 1 should fallback on not-found only (comma): %+v", entries[1])
	}
	if !entries[2].IsDirect {
		t.Errorf("entry 2 should be direct: %+v", entries[2])
	}
}

func TestGolangDetect_Off(t *testing.T) {
	env := []string{"GOPROXY=off"}
	gm := &GolangManager{}
	_, active := gm.Detect(env)
	if active {
		t.Error("expected inactive when GOPROXY=off")
	}
}

func TestGolangInjectEnv_AppendsDirect(t *testing.T) {
	env := []string{"HOME=/home/user"}
	gm := &GolangManager{}
	injected := gm.InjectEnv(env, "http://localhost:8080")

	found := map[string]string{}
	for _, e := range injected {
		parts := strings.SplitN(e, "=", 2)
		found[parts[0]] = parts[1]
	}

	if found["GOPROXY"] != "http://localhost:8080,direct" {
		t.Errorf("GOPROXY should end with ,direct, got %s", found["GOPROXY"])
	}
}

func TestGolangUpstreamURL_WithComma(t *testing.T) {
	gm := &GolangManager{}
	r, _ := http.NewRequest("GET", "http://localhost/github.com/foo/bar/@v/v1.2.3.zip", nil)
	got := gm.UpstreamURL("https://proxy.golang.org,direct", r)
	want := "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3.zip"
	if got != want {
		t.Errorf("UpstreamURL = %s, want %s", got, want)
	}
}
```

- [ ] **Step 2: Run tests — verify new ones fail**

```bash
go test ./internal/manager/ -v -run "Chain|_Off|_AppendsDirect"
```

Expected: compilation errors (ParseUpstreamChain, ProxyEntry not defined).

- [ ] **Step 3: Add ProxyEntry type to `internal/manager/manager.go`**

Add after the `PackageRequest` type:

```go
// ProxyEntry represents one entry in a GOPROXY chain.
type ProxyEntry struct {
	URL               string
	FallbackOnNotFound bool // comma separator: try next on 404/410
	FallbackOnError    bool // pipe separator: try next on any error
	IsDirect          bool // "direct" keyword
	IsOff             bool // "off" keyword
}
```

- [ ] **Step 4: Implement ParseUpstreamChain and update Detect/InjectEnv in `internal/manager/golang.go`**

Replace the full file content with:

```go
package manager

import (
	"fmt"
	"net/http"
	"strings"
)

type GolangManager struct{}

func (g *GolangManager) Name() string { return "go" }

func (g *GolangManager) Detect(env []string) (string, bool) {
	for _, e := range env {
		if val, ok := strings.CutPrefix(e, "GOPROXY="); ok && val != "" {
			if val == "off" {
				return val, false
			}
			return val, true
		}
	}
	return "https://proxy.golang.org,direct", true
}

func (g *GolangManager) InjectEnv(env []string, proxyAddr string) []string {
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		key := strings.SplitN(e, "=", 2)[0]
		switch key {
		case "GOPROXY", "GONOSUMDB", "GONOSUMCHECK":
			continue
		default:
			filtered = append(filtered, e)
		}
	}
	return append(filtered,
		"GOPROXY="+proxyAddr+",direct",
		"GONOSUMDB=*",
		"GONOSUMCHECK=*",
	)
}

func (g *GolangManager) Match(r *http.Request) bool {
	return strings.Contains(r.URL.Path, "/@v/")
}

func (g *GolangManager) Parse(r *http.Request) (PackageRequest, error) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	module, rest, ok := strings.Cut(path, "/@v/")
	if !ok {
		return PackageRequest{}, fmt.Errorf("not a Go module request: %s", r.URL.Path)
	}

	if rest == "list" {
		return PackageRequest{Module: module, Type: "list"}, nil
	}

	lastDot := strings.LastIndex(rest, ".")
	if lastDot < 0 {
		return PackageRequest{}, fmt.Errorf("cannot parse version/type from: %s", rest)
	}

	version := rest[:lastDot]
	typ := rest[lastDot+1:]

	return PackageRequest{
		Module:  module,
		Version: version,
		Type:    typ,
	}, nil
}

func (g *GolangManager) UpstreamURL(upstream string, r *http.Request) string {
	base := strings.Split(upstream, ",")[0]
	base = strings.Split(base, "|")[0]
	base = strings.TrimRight(base, "/")
	return base + r.URL.Path
}

// ParseUpstreamChain parses a GOPROXY value into a chain of proxy entries.
// Supports comma-separated (fallback on 404/410), pipe-separated (fallback on any error),
// "direct" (VCS fallback), and "off" (no downloads).
func (g *GolangManager) ParseUpstreamChain(goproxy string) []ProxyEntry {
	if goproxy == "off" {
		return []ProxyEntry{{IsOff: true}}
	}

	var entries []ProxyEntry

	// First split by comma, but we need to track | vs , separators.
	// Go's GOPROXY uses , and | as separators at the same level.
	// We scan character by character to build entries with correct separator info.
	current := ""
	for i := 0; i < len(goproxy); i++ {
		ch := goproxy[i]
		if ch == ',' || ch == '|' {
			if current != "" {
				entry := makeEntry(current)
				if ch == ',' {
					entry.FallbackOnNotFound = true
				} else {
					entry.FallbackOnError = true
				}
				entries = append(entries, entry)
			}
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		entries = append(entries, makeEntry(current))
	}

	return entries
}

func makeEntry(s string) ProxyEntry {
	s = strings.TrimSpace(s)
	switch s {
	case "direct":
		return ProxyEntry{URL: "direct", IsDirect: true}
	case "off":
		return ProxyEntry{IsOff: true}
	default:
		return ProxyEntry{URL: s}
	}
}
```

- [ ] **Step 5: Fix existing test for InjectEnv (now includes `,direct`)**

In `internal/manager/golang_test.go`, update `TestGolangInjectEnv`:

Change:
```go
	if found["GOPROXY"] != "http://localhost:8080" {
```
To:
```go
	if found["GOPROXY"] != "http://localhost:8080,direct" {
```

- [ ] **Step 6: Run all manager tests**

```bash
go test ./internal/manager/ -v
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add internal/manager/
git commit -m "feat: parse GOPROXY chain with comma/pipe/direct/off support"
```

---

### Task 2: Proxy forward with fallback chain

**Files:**
- Modify: `internal/proxy/proxy.go`
- Modify: `internal/proxy/proxy_test.go`

- [ ] **Step 1: Add new proxy tests for fallback behavior in `internal/proxy/proxy_test.go`**

Append these tests:

```go
func TestProxyFallbackChain_FirstFails404_SecondSucceeds(t *testing.T) {
	upstream1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer upstream1.Close()

	upstream2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"v1.0.0","Time":"2020-01-01T00:00:00Z"}`))
	}))
	defer upstream2.Close()

	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
	}))
	defer checkSrv.Close()

	gm := &manager.GolangManager{}
	client := check.NewClient(checkSrv.URL, 5*time.Second, 100*time.Millisecond)
	spinner := ui.NewSpinner(io.Discard, true)

	chain := upstream1.URL + "," + upstream2.URL
	p := New([]ActiveManager{{Manager: gm, Upstream: chain}}, client, spinner)
	srv := httptest.NewServer(p)
	defer srv.Close()
	defer spinner.Shutdown()

	resp, err := http.Get(srv.URL + "/github.com/foo/bar/@v/v1.0.0.info")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("expected 200 from fallback, got %d", resp.StatusCode)
	}
	if string(body) == "" {
		t.Error("expected non-empty body from second upstream")
	}
}

func TestProxyFallbackChain_PipeFallsBackOnAnyError(t *testing.T) {
	upstream1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream1.Close()

	upstream2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"v1.0.0","Time":"2020-01-01T00:00:00Z"}`))
	}))
	defer upstream2.Close()

	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
	}))
	defer checkSrv.Close()

	gm := &manager.GolangManager{}
	client := check.NewClient(checkSrv.URL, 5*time.Second, 100*time.Millisecond)
	spinner := ui.NewSpinner(io.Discard, true)

	// pipe separator: fallback on ANY error
	chain := upstream1.URL + "|" + upstream2.URL
	p := New([]ActiveManager{{Manager: gm, Upstream: chain}}, client, spinner)
	srv := httptest.NewServer(p)
	defer srv.Close()
	defer spinner.Shutdown()

	resp, err := http.Get(srv.URL + "/github.com/foo/bar/@v/v1.0.0.info")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("expected 200 from pipe fallback, got %d", resp.StatusCode)
	}
	if string(body) == "" {
		t.Error("expected non-empty body from second upstream")
	}
}

func TestProxyFallbackChain_CommaDoesNotFallbackOn500(t *testing.T) {
	upstream1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream1.Close()

	upstream2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should not reach"))
	}))
	defer upstream2.Close()

	gm := &manager.GolangManager{}
	client := check.NewClient("http://127.0.0.1:1", 1*time.Second, 100*time.Millisecond)
	spinner := ui.NewSpinner(io.Discard, true)

	// comma separator: only fallback on 404/410
	chain := upstream1.URL + "," + upstream2.URL
	p := New([]ActiveManager{{Manager: gm, Upstream: chain}}, client, spinner)
	srv := httptest.NewServer(p)
	defer srv.Close()
	defer spinner.Shutdown()

	resp, err := http.Get(srv.URL + "/github.com/foo/bar/@v/v1.0.0.info")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// comma separator does NOT fallback on 500, so we get the 500 from upstream1
	if resp.StatusCode != 500 {
		t.Errorf("expected 500 (no fallback on comma for 500), got %d", resp.StatusCode)
	}
}

func TestProxyFallbackChain_DirectEntrySkipped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	gm := &manager.GolangManager{}
	client := check.NewClient("http://127.0.0.1:1", 1*time.Second, 100*time.Millisecond)
	spinner := ui.NewSpinner(io.Discard, true)

	chain := upstream.URL + ",direct"
	p := New([]ActiveManager{{Manager: gm, Upstream: chain}}, client, spinner)
	srv := httptest.NewServer(p)
	defer srv.Close()
	defer spinner.Shutdown()

	resp, err := http.Get(srv.URL + "/github.com/foo/bar/@v/v1.0.0.info")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// upstream 404s, direct is skipped, proxy returns 404
	if resp.StatusCode != 404 {
		t.Errorf("expected 404 when chain exhausted, got %d", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run tests — verify new ones fail**

```bash
go test ./internal/proxy/ -v -run "Fallback"
```

Expected: failures (proxy doesn't handle chains yet).

- [ ] **Step 3: Rewrite proxy.go forward method to handle chains**

Replace the `handle` and `forward` methods in `internal/proxy/proxy.go` with:

```go
func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	for _, am := range p.managers {
		if !am.Manager.Match(r) {
			continue
		}

		pkg, err := am.Manager.Parse(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if pkg.NeedsCheck() {
			if !p.checkPackage(r.Context(), w, pkg) {
				return
			}
		}

		p.forwardWithChain(w, r, am)
		return
	}

	http.NotFound(w, r)
}

func (p *Proxy) forwardWithChain(w http.ResponseWriter, r *http.Request, am ActiveManager) {
	gm, ok := am.Manager.(*manager.GolangManager)
	if !ok {
		// Non-Go managers: simple forward to first URL (existing behavior)
		upstreamURL := am.Manager.UpstreamURL(am.Upstream, r)
		p.forward(w, r, upstreamURL)
		return
	}

	entries := gm.ParseUpstreamChain(am.Upstream)

	for _, entry := range entries {
		if entry.IsDirect || entry.IsOff {
			continue
		}

		upstreamURL := strings.TrimRight(entry.URL, "/") + r.URL.Path
		statusCode, respBody, respHeaders := p.tryForward(r, upstreamURL)

		shouldFallback := false
		if entry.FallbackOnError && statusCode == 0 {
			// Network error + pipe separator: try next
			shouldFallback = true
		} else if (entry.FallbackOnNotFound || entry.FallbackOnError) && (statusCode == http.StatusNotFound || statusCode == http.StatusGone) {
			shouldFallback = true
		} else if entry.FallbackOnError && statusCode >= 400 {
			shouldFallback = true
		}

		if shouldFallback {
			if respBody != nil {
				respBody.Close()
			}
			continue
		}

		if statusCode == 0 {
			// Network error, no more fallback
			http.Error(w, "upstream unreachable", http.StatusBadGateway)
			return
		}

		// Success or non-fallback error: return the response
		for k, vv := range respHeaders {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(statusCode)
		if respBody != nil {
			io.Copy(w, respBody)
			respBody.Close()
		}
		return
	}

	// All entries exhausted
	http.NotFound(w, r)
}

// tryForward makes a request and returns status, body, headers.
// Returns statusCode=0 on network error.
func (p *Proxy) tryForward(r *http.Request, upstreamURL string) (int, io.ReadCloser, http.Header) {
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		return 0, nil, nil
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, nil
	}

	return resp.StatusCode, resp.Body, resp.Header
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, upstreamURL string) {
	req, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
```

Add this import at the top (alongside existing ones):
```go
"strings"
```

Also add `*manager.GolangManager` type assertion import — you'll need to update the import block to include the `strings` package.

- [ ] **Step 4: Run all proxy tests**

```bash
go test ./internal/proxy/ -v
```

Expected: all tests pass (old + new).

- [ ] **Step 5: Run all tests to check nothing broke**

```bash
go test ./... -v -race -count=1
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/
git commit -m "feat: proxy implements GOPROXY fallback chain with comma/pipe semantics"
```

---

### Task 3: README polish

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README**

Changes:
1. In "Show me" section: reframe `soa serve` as one option, not the required first step. The check server is a separate service — could be remote.
2. Remove any implication that the checker must run locally.
3. Verify the 🛃 emoji is present in the title.

Replace the full "Show me" section with:

```markdown
## Show me

Prefix any command with `soa`:
```bash
soa make build
```

That's it. `soa` sets up a proxy, rewires the right env vars, and checks every dependency download before it lands. You'll see this while it works:

```
[soa] ⠋ scanning github.com/gin-gonic/gin@v1.9.1
[soa] ✓ github.com/gin-gonic/gin@v1.9.1 allowed
```

If something gets blocked:
```
[soa] ✗ github.com/sketchy/lib@v0.0.1 blocked: published 2 days ago
```

`soa` wraps anything — your toolchain, your aliases, your scripts:
```bash
soa go test ./...
soa gogo build          # custom alias? no problem
soa ./scripts/deps.sh   # anything that pulls packages
```

### Running the check server

`soa` sends checks to whatever `check_url` points to in your config. A reference implementation ships with the binary:

```bash
soa serve
```

This starts a check server that blocks packages published less than 7 days ago. Point `check_url` at any endpoint that speaks the [check API](pkg/checkapi/checkapi.go) — your own, a shared team server, a cloud service.
```

Replace the FAQ entry about the check server:

From:
```markdown
**Can I use my own check server?**
Yes. Point `check_url` to any server that speaks the [check API](pkg/checkapi/checkapi.go). The built-in `soa serve` is just a reference implementation.
```

To:
```markdown
**Can I use my own check server?**
Yes. `soa` talks to whatever `check_url` points to. The built-in `soa serve` is just a reference implementation — swap it for anything that speaks the [check API](pkg/checkapi/checkapi.go).
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: clarify check server is remote-friendly, not local-only"
```

---

### Task 4: Full verification and PR

- [ ] **Step 1: Run the full test suite**

```bash
go vet ./...
go test ./... -v -race -count=1
```

Expected: all pass, no vet warnings.

- [ ] **Step 2: Switch to ariary, push, and create PR**

```bash
gh auth switch --user ariary
git push -u origin feat/goproxy-chain
gh pr create --title "feat: handle full GOPROXY chain and polish README" --body "$(cat <<'EOF'
## Summary

- **GOPROXY fallback chain** — proxy now tries each entry in order: `,` separator falls back on 404/410, `|` separator falls back on any error, `direct` entries are skipped (Go handles VCS fallback itself)
- **`GOPROXY=off` handling** — Go manager deactivates, subprocess runs transparently
- **`,direct` injection** — soa injects `GOPROXY=http://localhost:<port>,direct` so private modules not on any proxy can still be fetched via VCS
- **README polish** — check server framed as remote-friendly, not local-only; `soa serve` presented as one option, not a required step

## Test plan

- [x] New tests for proxy chain parsing (comma, pipe, mixed, off, direct)
- [x] New tests for proxy fallback (404 tries next, 500 stops on comma, 500 continues on pipe, direct skipped)
- [x] Existing tests updated for `,direct` injection
- [x] Full suite passes with `-race`
- [ ] Manual: `soa go get` against real proxy.golang.org with default GOPROXY

EOF
)"
gh auth switch --user antoine-rabenandrasana_qonto
```
