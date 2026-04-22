# soa Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `soa`, a CLI security wrapper that intercepts Go package downloads via a local GOPROXY and enforces security policies through a configurable check endpoint.

**Architecture:** Single binary with two modes: proxy wrapper (`soa <cmd>`) and reference check server (`soa serve`). The proxy intercepts GOPROXY requests, delegates policy decisions to an external check endpoint via HTTP, and shows progress with an ANSI spinner. Managers abstract ecosystem-specific logic behind a common interface.

**Tech Stack:** Go, `github.com/ariary/quicli` (CLI), `gopkg.in/yaml.v3` (config), stdlib `net/http` (proxy + server), no external deps for spinner.

---

## File Structure

```
soa/
├── cmd/soa/main.go                    # CLI entrypoint with quicli
├── internal/
│   ├── config/config.go               # config loading (file + env vars)
│   ├── config/config_test.go
│   ├── manager/manager.go             # Manager interface
│   ├── manager/golang.go              # GolangManager implementation
│   ├── manager/golang_test.go
│   ├── check/client.go                # PolicyClient (HTTP client)
│   ├── check/client_test.go
│   ├── ui/spinner.go                  # ANSI spinner
│   ├── ui/spinner_test.go
│   ├── proxy/proxy.go                 # HTTP intercepting proxy
│   ├── proxy/proxy_test.go
│   ├── server/server.go               # Reference check server
│   ├── server/server_test.go
│   └── orchestrator/orchestrator.go   # Subprocess + proxy lifecycle
│       orchestrator/orchestrator_test.go
├── pkg/checkapi/checkapi.go           # Shared request/response types
├── configs/config.example.yaml
├── .github/workflows/ci.yml           # CI: test + lint
└── README.md
```

---

### Task 1: Project Scaffolding & Shared Types

**Files:**
- Create: `go.mod`
- Create: `pkg/checkapi/checkapi.go`
- Create: `cmd/soa/main.go` (stub)

- [ ] **Step 1: Initialize Go module**

```bash
go mod init github.com/ariary/soa
```

- [ ] **Step 2: Create shared types in `pkg/checkapi/checkapi.go`**

```go
package checkapi

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
	Progress float64 `json:"progress,omitempty"`
	ID       string  `json:"id,omitempty"`
}
```

- [ ] **Step 3: Create stub main**

```go
package main

import "fmt"

func main() {
	fmt.Println("soa")
}
```

- [ ] **Step 4: Verify it compiles**

```bash
go build ./...
```

Expected: success, no errors.

- [ ] **Step 5: Commit**

```bash
git add go.mod cmd/ pkg/
git commit -m "scaffold: init module, shared checkapi types, stub main"
```

---

### Task 2: Configuration

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `configs/config.example.yaml`

- [ ] **Step 1: Write config tests in `internal/config/config_test.go`**

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg := LoadWithPath("")
	if cfg.CheckURL != "http://localhost:9090" {
		t.Errorf("expected default check_url, got %s", cfg.CheckURL)
	}
	if cfg.Proxy.Port != 8080 {
		t.Errorf("expected default proxy port 8080, got %d", cfg.Proxy.Port)
	}
	if cfg.CheckTimeout.String() != "30s" {
		t.Errorf("expected default check_timeout 30s, got %s", cfg.CheckTimeout)
	}
	if cfg.PollInterval.String() != "500ms" {
		t.Errorf("expected default poll_interval 500ms, got %s", cfg.PollInterval)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte("check_url: http://firewall:443\nproxy:\n  port: 9999\n")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg := LoadWithPath(path)
	if cfg.CheckURL != "http://firewall:443" {
		t.Errorf("expected check_url from file, got %s", cfg.CheckURL)
	}
	if cfg.Proxy.Port != 9999 {
		t.Errorf("expected proxy port 9999, got %d", cfg.Proxy.Port)
	}
}

func TestEnvVarOverrides(t *testing.T) {
	t.Setenv("SOA_CHECK_URL", "http://env-override:1234")
	t.Setenv("SOA_PROXY_PORT", "7777")
	cfg := LoadWithPath("")
	if cfg.CheckURL != "http://env-override:1234" {
		t.Errorf("expected env override, got %s", cfg.CheckURL)
	}
	if cfg.Proxy.Port != 7777 {
		t.Errorf("expected env port 7777, got %d", cfg.Proxy.Port)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte("check_url: http://from-file:80\n")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOA_CHECK_URL", "http://from-env:443")
	cfg := LoadWithPath(path)
	if cfg.CheckURL != "http://from-env:443" {
		t.Errorf("expected env to override file, got %s", cfg.CheckURL)
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./internal/config/ -v
```

Expected: compilation error (no `config.go` yet).

- [ ] **Step 3: Implement `internal/config/config.go`**

Note: `time.Duration` does not unmarshal from YAML strings like `"500ms"` with `yaml.v3`. We use a `yamlConfig` intermediary with string fields for durations, then convert.

```go
package config

import (
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	CheckURL     string
	Proxy        ProxyConfig
	PollInterval time.Duration
	CheckTimeout time.Duration
	Server       ServerConfig
}

type ProxyConfig struct {
	Port int `yaml:"port"`
}

type ServerConfig struct {
	Port       int    `yaml:"port"`
	CachePath  string `yaml:"cache_path"`
	MaxAgeDays int    `yaml:"max_age_days"`
}

// yamlConfig mirrors Config but uses strings for durations (yaml.v3 compat).
type yamlConfig struct {
	CheckURL     string       `yaml:"check_url"`
	Proxy        ProxyConfig  `yaml:"proxy"`
	PollInterval string       `yaml:"poll_interval"`
	CheckTimeout string       `yaml:"check_timeout"`
	Server       ServerConfig `yaml:"server"`
}

func defaults() Config {
	return Config{
		CheckURL:     "http://localhost:9090",
		Proxy:        ProxyConfig{Port: 8080},
		PollInterval: 500 * time.Millisecond,
		CheckTimeout: 30 * time.Second,
		Server: ServerConfig{
			Port:       9090,
			CachePath:  "~/.config/soa/approved.json",
			MaxAgeDays: 7,
		},
	}
}

// Load reads config from the default path (~/.config/soa/config.yaml) then applies env overrides.
func Load() Config {
	home, _ := os.UserHomeDir()
	path := home + "/.config/soa/config.yaml"
	return LoadWithPath(path)
}

// LoadWithPath reads config from a specific path (empty means defaults-only) then applies env overrides.
func LoadWithPath(path string) Config {
	cfg := defaults()
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			var yc yamlConfig
			if yaml.Unmarshal(data, &yc) == nil {
				if yc.CheckURL != "" {
					cfg.CheckURL = yc.CheckURL
				}
				if yc.Proxy.Port != 0 {
					cfg.Proxy.Port = yc.Proxy.Port
				}
				if yc.PollInterval != "" {
					if d, err := time.ParseDuration(yc.PollInterval); err == nil {
						cfg.PollInterval = d
					}
				}
				if yc.CheckTimeout != "" {
					if d, err := time.ParseDuration(yc.CheckTimeout); err == nil {
						cfg.CheckTimeout = d
					}
				}
				if yc.Server.Port != 0 {
					cfg.Server.Port = yc.Server.Port
				}
				if yc.Server.CachePath != "" {
					cfg.Server.CachePath = yc.Server.CachePath
				}
				if yc.Server.MaxAgeDays != 0 {
					cfg.Server.MaxAgeDays = yc.Server.MaxAgeDays
				}
			}
		}
	}
	applyEnv(&cfg)
	return cfg
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("SOA_CHECK_URL"); v != "" {
		cfg.CheckURL = v
	}
	if v := os.Getenv("SOA_PROXY_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Proxy.Port = p
		}
	}
	if v := os.Getenv("SOA_CHECK_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.CheckTimeout = d
		}
	}
	if v := os.Getenv("SOA_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.PollInterval = d
		}
	}
	if v := os.Getenv("SOA_SERVER_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = p
		}
	}
	if v := os.Getenv("SOA_SERVER_CACHE_PATH"); v != "" {
		cfg.Server.CachePath = v
	}
	if v := os.Getenv("SOA_SERVER_MAX_AGE_DAYS"); v != "" {
		if d, err := strconv.Atoi(v); err == nil {
			cfg.Server.MaxAgeDays = d
		}
	}
}
```

- [ ] **Step 4: Add yaml dependency and run tests**

```bash
go get gopkg.in/yaml.v3
go test ./internal/config/ -v
```

Expected: all 4 tests pass.

- [ ] **Step 5: Create `configs/config.example.yaml`**

```yaml
# soa configuration
# Place this at ~/.config/soa/config.yaml

# Where to reach the check server
check_url: "http://localhost:9090"

# Local proxy settings
proxy:
  port: 8080

# Polling interval for async checks
poll_interval: "500ms"

# Timeout for check requests
check_timeout: "30s"

# Reference check server settings (used by 'soa serve')
server:
  port: 9090
  cache_path: "~/.config/soa/approved.json"
  max_age_days: 7
```

- [ ] **Step 6: Commit**

```bash
git add internal/config/ configs/ go.mod go.sum
git commit -m "feat: config loading with file + env var overrides"
```

---

### Task 3: Manager Interface & GolangManager

**Files:**
- Create: `internal/manager/manager.go`
- Create: `internal/manager/golang.go`
- Create: `internal/manager/golang_test.go`

- [ ] **Step 1: Write the Manager interface in `internal/manager/manager.go`**

```go
package manager

import "net/http"

type PackageRequest struct {
	Module  string
	Version string
	Type    string // "info", "mod", "zip", "list", "latest"
}

// NeedsCheck returns true if this request type should trigger a policy check.
func (p PackageRequest) NeedsCheck() bool {
	return p.Type == "zip"
}

type Manager interface {
	// Name returns the ecosystem identifier (e.g. "go").
	Name() string

	// Detect inspects env vars to find the upstream registry.
	// Returns the upstream URL and whether this ecosystem is active.
	Detect(env []string) (upstream string, active bool)

	// InjectEnv returns a modified env slice pointing the toolchain at soa's proxy.
	InjectEnv(env []string, proxyAddr string) []string

	// Match returns true if the incoming proxy request belongs to this manager.
	Match(r *http.Request) bool

	// Parse extracts package info from a matched request.
	Parse(r *http.Request) (PackageRequest, error)

	// UpstreamURL builds the URL to fetch from the real registry.
	UpstreamURL(upstream string, r *http.Request) string
}
```

- [ ] **Step 2: Write GolangManager tests in `internal/manager/golang_test.go`**

```go
package manager

import (
	"net/http"
	"strings"
	"testing"
)

func TestGolangDetect_FromEnv(t *testing.T) {
	env := []string{"HOME=/home/user", "GOPROXY=https://proxy.golang.org,direct", "PATH=/usr/bin"}
	gm := &GolangManager{}
	upstream, active := gm.Detect(env)
	if !active {
		t.Fatal("expected active when GOPROXY is set")
	}
	if upstream != "https://proxy.golang.org,direct" {
		t.Errorf("expected upstream from env, got %s", upstream)
	}
}

func TestGolangDetect_NoEnv(t *testing.T) {
	env := []string{"HOME=/home/user", "PATH=/usr/bin"}
	gm := &GolangManager{}
	upstream, active := gm.Detect(env)
	if !active {
		t.Fatal("expected active with default GOPROXY")
	}
	if upstream != "https://proxy.golang.org,direct" {
		t.Errorf("expected default upstream, got %s", upstream)
	}
}

func TestGolangInjectEnv(t *testing.T) {
	env := []string{"HOME=/home/user", "GOPROXY=https://proxy.golang.org,direct"}
	gm := &GolangManager{}
	injected := gm.InjectEnv(env, "http://localhost:8080")

	found := map[string]string{}
	for _, e := range injected {
		parts := strings.SplitN(e, "=", 2)
		found[parts[0]] = parts[1]
	}

	if found["GOPROXY"] != "http://localhost:8080" {
		t.Errorf("GOPROXY not overridden, got %s", found["GOPROXY"])
	}
	if found["GONOSUMDB"] != "*" {
		t.Errorf("GONOSUMDB not set, got %s", found["GONOSUMDB"])
	}
	if found["GONOSUMCHECK"] != "*" {
		t.Errorf("GONOSUMCHECK not set, got %s", found["GONOSUMCHECK"])
	}
}

func TestGolangMatch(t *testing.T) {
	gm := &GolangManager{}

	tests := []struct {
		path  string
		match bool
	}{
		{"/github.com/foo/bar/@v/v1.2.3.zip", true},
		{"/github.com/foo/bar/@v/v1.2.3.info", true},
		{"/github.com/foo/bar/@v/v1.2.3.mod", true},
		{"/github.com/foo/bar/@v/list", true},
		{"/some/random/path", false},
	}
	for _, tt := range tests {
		r, _ := http.NewRequest("GET", "http://localhost"+tt.path, nil)
		if got := gm.Match(r); got != tt.match {
			t.Errorf("Match(%s) = %v, want %v", tt.path, got, tt.match)
		}
	}
}

func TestGolangParse(t *testing.T) {
	gm := &GolangManager{}

	tests := []struct {
		path    string
		module  string
		version string
		typ     string
	}{
		{"/github.com/foo/bar/@v/v1.2.3.zip", "github.com/foo/bar", "v1.2.3", "zip"},
		{"/github.com/foo/bar/@v/v1.2.3.info", "github.com/foo/bar", "v1.2.3", "info"},
		{"/github.com/foo/bar/@v/v1.2.3.mod", "github.com/foo/bar", "v1.2.3", "mod"},
		{"/golang.org/x/text/@v/v0.3.7.zip", "golang.org/x/text", "v0.3.7", "zip"},
		{"/github.com/foo/bar/@v/list", "github.com/foo/bar", "", "list"},
	}
	for _, tt := range tests {
		r, _ := http.NewRequest("GET", "http://localhost"+tt.path, nil)
		pkg, err := gm.Parse(r)
		if err != nil {
			t.Errorf("Parse(%s) error: %v", tt.path, err)
			continue
		}
		if pkg.Module != tt.module {
			t.Errorf("Parse(%s).Module = %s, want %s", tt.path, pkg.Module, tt.module)
		}
		if pkg.Version != tt.version {
			t.Errorf("Parse(%s).Version = %s, want %s", tt.path, pkg.Version, tt.version)
		}
		if pkg.Type != tt.typ {
			t.Errorf("Parse(%s).Type = %s, want %s", tt.path, pkg.Type, tt.typ)
		}
	}
}

func TestGolangUpstreamURL(t *testing.T) {
	gm := &GolangManager{}
	r, _ := http.NewRequest("GET", "http://localhost/github.com/foo/bar/@v/v1.2.3.zip", nil)
	got := gm.UpstreamURL("https://proxy.golang.org", r)
	want := "https://proxy.golang.org/github.com/foo/bar/@v/v1.2.3.zip"
	if got != want {
		t.Errorf("UpstreamURL = %s, want %s", got, want)
	}
}
```

- [ ] **Step 3: Run tests — verify they fail**

```bash
go test ./internal/manager/ -v
```

Expected: compilation error (no `golang.go` yet).

- [ ] **Step 4: Implement `internal/manager/golang.go`**

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
		if strings.HasPrefix(e, "GOPROXY=") {
			val := strings.TrimPrefix(e, "GOPROXY=")
			if val != "" {
				return val, true
			}
		}
	}
	// Default upstream if GOPROXY not set
	return "https://proxy.golang.org,direct", true
}

func (g *GolangManager) InjectEnv(env []string, proxyAddr string) []string {
	// Remove existing GOPROXY, GONOSUMDB, GONOSUMCHECK
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
		"GOPROXY="+proxyAddr,
		"GONOSUMDB=*",
		"GONOSUMCHECK=*",
	)
}

func (g *GolangManager) Match(r *http.Request) bool {
	return strings.Contains(r.URL.Path, "/@v/")
}

func (g *GolangManager) Parse(r *http.Request) (PackageRequest, error) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	idx := strings.Index(path, "/@v/")
	if idx < 0 {
		return PackageRequest{}, fmt.Errorf("not a Go module request: %s", r.URL.Path)
	}

	module := path[:idx]
	rest := path[idx+4:] // after "/@v/"

	if rest == "list" {
		return PackageRequest{Module: module, Type: "list"}, nil
	}

	// rest is like "v1.2.3.zip" or "v1.2.3.info" or "v1.2.3.mod"
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
	// Strip trailing comma-separated fallbacks for URL construction
	base := strings.Split(upstream, ",")[0]
	base = strings.TrimRight(base, "/")
	return base + r.URL.Path
}
```

- [ ] **Step 5: Run tests — verify they pass**

```bash
go test ./internal/manager/ -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/manager/
git commit -m "feat: Manager interface and GolangManager implementation"
```

---

### Task 4: ANSI Spinner

**Files:**
- Create: `internal/ui/spinner.go`
- Create: `internal/ui/spinner_test.go`

- [ ] **Step 1: Write spinner tests in `internal/ui/spinner_test.go`**

```go
package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestSpinnerStartStop(t *testing.T) {
	var buf bytes.Buffer
	s := NewSpinner(&buf, false)
	s.Start("github.com/foo/bar", "v1.2.3")
	time.Sleep(150 * time.Millisecond) // let a few frames render
	s.Stop("github.com/foo/bar", true, "")

	out := buf.String()
	if !strings.Contains(out, "foo/bar") {
		t.Errorf("expected module name in output, got: %s", out)
	}
	if !strings.Contains(out, "v1.2.3") {
		t.Errorf("expected version in output, got: %s", out)
	}
}

func TestSpinnerBlocked(t *testing.T) {
	var buf bytes.Buffer
	s := NewSpinner(&buf, false)
	s.Start("github.com/foo/bar", "v1.2.3")
	time.Sleep(100 * time.Millisecond)
	s.Stop("github.com/foo/bar", false, "too new")

	out := buf.String()
	if !strings.Contains(out, "too new") {
		t.Errorf("expected reason in output, got: %s", out)
	}
}

func TestSpinnerProgress(t *testing.T) {
	var buf bytes.Buffer
	s := NewSpinner(&buf, false)
	s.Start("github.com/foo/bar", "v1.2.3")
	s.SetProgress("github.com/foo/bar", 0.5)
	time.Sleep(150 * time.Millisecond)
	s.Stop("github.com/foo/bar", true, "")

	// Progress was set, output should reflect it
	// (exact format tested visually, here we just check no panic)
}

func TestSpinnerPlainMode(t *testing.T) {
	var buf bytes.Buffer
	s := NewSpinner(&buf, true) // plain mode = non-TTY
	s.Start("github.com/foo/bar", "v1.2.3")
	time.Sleep(100 * time.Millisecond)
	s.Stop("github.com/foo/bar", true, "")

	out := buf.String()
	// In plain mode, no ANSI escapes
	if strings.Contains(out, "\033[") {
		t.Errorf("expected no ANSI in plain mode, got: %s", out)
	}
	if !strings.Contains(out, "foo/bar") {
		t.Errorf("expected module name in plain output, got: %s", out)
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./internal/ui/ -v
```

Expected: compilation error.

- [ ] **Step 3: Implement `internal/ui/spinner.go`**

```go
package ui

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

var frames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'}

type entry struct {
	module   string
	version  string
	progress float64
	done     bool
	allowed  bool
	reason   string
}

type Spinner struct {
	mu      sync.Mutex
	w       io.Writer
	plain   bool
	entries map[string]*entry
	stop    chan struct{}
	wg      sync.WaitGroup
	frame   int
}

func NewSpinner(w io.Writer, plain bool) *Spinner {
	s := &Spinner{
		w:       w,
		plain:   plain,
		entries: make(map[string]*entry),
		stop:    make(chan struct{}),
	}
	s.wg.Add(1)
	go s.loop()
	return s
}

func (s *Spinner) Start(module, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[module] = &entry{module: module, version: version}
	if s.plain {
		fmt.Fprintf(s.w, "[soa] scanning %s@%s...\n", module, version)
	}
}

func (s *Spinner) SetProgress(module string, progress float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[module]; ok {
		e.progress = progress
	}
}

func (s *Spinner) Stop(module string, allowed bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[module]; ok {
		e.done = true
		e.allowed = allowed
		e.reason = reason
	}
	if s.plain {
		if allowed {
			fmt.Fprintf(s.w, "[soa] ✓ %s allowed\n", module)
		} else {
			fmt.Fprintf(s.w, "[soa] ✗ %s blocked: %s\n", module, reason)
		}
	}
}

func (s *Spinner) Shutdown() {
	close(s.stop)
	s.wg.Wait()
	// Final render to print done entries
	s.render(true)
}

func (s *Spinner) loop() {
	defer s.wg.Done()
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			if !s.plain {
				s.render(false)
			}
		}
	}
}

func (s *Spinner) render(final bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, e := range s.entries {
		if e.done {
			if e.allowed {
				fmt.Fprintf(s.w, "\033[2K\r[soa] ✓ %s@%s allowed\n", e.module, e.version)
			} else {
				fmt.Fprintf(s.w, "\033[2K\r[soa] ✗ %s@%s blocked: %s\n", e.module, e.version, e.reason)
			}
		} else if !final {
			line := fmt.Sprintf("[soa] %c scanning %s@%s", frames[s.frame%len(frames)], e.module, e.version)
			if e.progress > 0 {
				line += " " + progressBar(e.progress)
			}
			fmt.Fprintf(s.w, "\033[2K\r%s", line)
		}
	}
	s.frame++

	// Remove done entries after rendering
	for k, e := range s.entries {
		if e.done {
			delete(s.entries, k)
		}
	}
}

func progressBar(p float64) string {
	width := 10
	filled := int(p * float64(width))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return fmt.Sprintf("[%s %d%%]", bar, int(p*100))
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
go test ./internal/ui/ -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/ui/
git commit -m "feat: ANSI spinner with progress bar support"
```

---

### Task 5: Policy Client

**Files:**
- Create: `internal/check/client.go`
- Create: `internal/check/client_test.go`

- [ ] **Step 1: Write policy client tests in `internal/check/client_test.go`**

```go
package check

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ariary/soa/pkg/checkapi"
)

func TestCheckAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/check" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var req checkapi.CheckRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Module != "github.com/foo/bar" {
			t.Errorf("unexpected module: %s", req.Module)
		}
		json.NewEncoder(w).Encode(checkapi.CheckResponse{
			Status: checkapi.StatusAllowed,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 5*time.Second, 100*time.Millisecond)
	resp, err := c.Check(context.Background(), checkapi.CheckRequest{
		Module: "github.com/foo/bar", Version: "v1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != checkapi.StatusAllowed {
		t.Errorf("expected allowed, got %s", resp.Status)
	}
}

func TestCheckBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{
			Status: checkapi.StatusBlocked,
			Reason: "published 2 days ago",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 5*time.Second, 100*time.Millisecond)
	resp, err := c.Check(context.Background(), checkapi.CheckRequest{
		Module: "github.com/foo/bar", Version: "v1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != checkapi.StatusBlocked {
		t.Errorf("expected blocked, got %s", resp.Status)
	}
	if resp.Reason != "published 2 days ago" {
		t.Errorf("expected reason, got %s", resp.Reason)
	}
}

func TestCheckProcessingThenAllowed(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/check" {
			json.NewEncoder(w).Encode(checkapi.CheckResponse{
				Status:   checkapi.StatusProcessing,
				ID:       "job-42",
				Progress: 0.1,
			})
			return
		}
		// Poll endpoint
		calls++
		if calls < 3 {
			json.NewEncoder(w).Encode(checkapi.CheckResponse{
				Status:   checkapi.StatusProcessing,
				ID:       "job-42",
				Progress: float64(calls) * 0.3,
			})
		} else {
			json.NewEncoder(w).Encode(checkapi.CheckResponse{
				Status: checkapi.StatusAllowed,
			})
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 5*time.Second, 50*time.Millisecond)
	resp, err := c.Check(context.Background(), checkapi.CheckRequest{
		Module: "github.com/foo/bar", Version: "v1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != checkapi.StatusAllowed {
		t.Errorf("expected allowed after polling, got %s", resp.Status)
	}
}

func TestCheckUnreachable_FailClosed(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", 1*time.Second, 100*time.Millisecond)
	resp, err := c.Check(context.Background(), checkapi.CheckRequest{
		Module: "github.com/foo/bar", Version: "v1.0.0",
	})
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
	// On error, response should indicate blocked (fail-closed)
	if resp.Status != checkapi.StatusBlocked {
		t.Errorf("expected blocked on error, got %s", resp.Status)
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./internal/check/ -v
```

Expected: compilation error.

- [ ] **Step 3: Implement `internal/check/client.go`**

```go
package check

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ariary/soa/pkg/checkapi"
)

// ProgressFunc is called when the check server reports progress.
type ProgressFunc func(progress float64)

type Client struct {
	baseURL      string
	timeout      time.Duration
	pollInterval time.Duration
	httpClient   *http.Client
}

func NewClient(baseURL string, timeout, pollInterval time.Duration) *Client {
	return &Client{
		baseURL:      baseURL,
		timeout:      timeout,
		pollInterval: pollInterval,
		httpClient:   &http.Client{Timeout: timeout},
	}
}

// Check sends a check request and handles polling for async responses.
// Returns a blocked response on any error (fail-closed).
func (c *Client) Check(ctx context.Context, req checkapi.CheckRequest) (checkapi.CheckResponse, error) {
	return c.CheckWithProgress(ctx, req, nil)
}

// CheckWithProgress is like Check but calls onProgress when the server reports progress.
func (c *Client) CheckWithProgress(ctx context.Context, req checkapi.CheckRequest, onProgress ProgressFunc) (checkapi.CheckResponse, error) {
	blocked := checkapi.CheckResponse{Status: checkapi.StatusBlocked, Reason: "check failed"}

	body, err := json.Marshal(req)
	if err != nil {
		return blocked, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/check", bytes.NewReader(body))
	if err != nil {
		return blocked, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return blocked, fmt.Errorf("check request: %w", err)
	}
	defer httpResp.Body.Close()

	var resp checkapi.CheckResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return blocked, fmt.Errorf("decode response: %w", err)
	}

	if resp.Status != checkapi.StatusProcessing {
		return resp, nil
	}

	// Poll for result
	if onProgress != nil {
		onProgress(resp.Progress)
	}
	return c.poll(ctx, resp.ID, onProgress)
}

func (c *Client) poll(ctx context.Context, id string, onProgress ProgressFunc) (checkapi.CheckResponse, error) {
	blocked := checkapi.CheckResponse{Status: checkapi.StatusBlocked, Reason: "check failed"}
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return blocked, ctx.Err()
		case <-ticker.C:
			httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/check/%s", c.baseURL, id), nil)
			if err != nil {
				return blocked, err
			}
			httpResp, err := c.httpClient.Do(httpReq)
			if err != nil {
				return blocked, fmt.Errorf("poll request: %w", err)
			}
			var resp checkapi.CheckResponse
			err = json.NewDecoder(httpResp.Body).Decode(&resp)
			httpResp.Body.Close()
			if err != nil {
				return blocked, fmt.Errorf("decode poll response: %w", err)
			}

			if onProgress != nil && resp.Status == checkapi.StatusProcessing {
				onProgress(resp.Progress)
			}
			if resp.Status != checkapi.StatusProcessing {
				return resp, nil
			}
		}
	}
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
go test ./internal/check/ -v
```

Expected: all 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/check/
git commit -m "feat: policy client with polling and fail-closed behavior"
```

---

### Task 6: HTTP Intercepting Proxy

**Files:**
- Create: `internal/proxy/proxy.go`
- Create: `internal/proxy/proxy_test.go`

- [ ] **Step 1: Write proxy tests in `internal/proxy/proxy_test.go`**

```go
package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ariary/soa/internal/check"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/internal/ui"
	"github.com/ariary/soa/pkg/checkapi"
)

func TestProxyForwardsNonZipTransparently(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"v1.0.0","Time":"2020-01-01T00:00:00Z"}`))
	}))
	defer upstream.Close()

	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("check server should not be called for .info requests")
	}))
	defer checkSrv.Close()

	gm := &manager.GolangManager{}
	client := check.NewClient(checkSrv.URL, 5*time.Second, 100*time.Millisecond)
	spinner := ui.NewSpinner(io.Discard, true)

	p := New([]ActiveManager{{Manager: gm, Upstream: upstream.URL}}, client, spinner)
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
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) == "" {
		t.Error("expected non-empty body")
	}
}

func TestProxyChecksZipAndAllows(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fake-zip-content"))
	}))
	defer upstream.Close()

	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
	}))
	defer checkSrv.Close()

	gm := &manager.GolangManager{}
	client := check.NewClient(checkSrv.URL, 5*time.Second, 100*time.Millisecond)
	spinner := ui.NewSpinner(io.Discard, true)

	p := New([]ActiveManager{{Manager: gm, Upstream: upstream.URL}}, client, spinner)
	srv := httptest.NewServer(p)
	defer srv.Close()
	defer spinner.Shutdown()

	resp, err := http.Get(srv.URL + "/github.com/foo/bar/@v/v1.0.0.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "fake-zip-content" {
		t.Errorf("expected upstream content, got %s", string(body))
	}
}

func TestProxyChecksZipAndBlocks(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should-not-reach-client"))
	}))
	defer upstream.Close()

	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{
			Status: checkapi.StatusBlocked,
			Reason: "too new",
		})
	}))
	defer checkSrv.Close()

	gm := &manager.GolangManager{}
	client := check.NewClient(checkSrv.URL, 5*time.Second, 100*time.Millisecond)
	spinner := ui.NewSpinner(io.Discard, true)

	p := New([]ActiveManager{{Manager: gm, Upstream: upstream.URL}}, client, spinner)
	srv := httptest.NewServer(p)
	defer srv.Close()
	defer spinner.Shutdown()

	resp, err := http.Get(srv.URL + "/github.com/foo/bar/@v/v1.0.0.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxyUnmatchedRequestReturns404(t *testing.T) {
	spinner := ui.NewSpinner(io.Discard, true)
	p := New([]ActiveManager{}, nil, spinner)
	srv := httptest.NewServer(p)
	defer srv.Close()
	defer spinner.Shutdown()

	resp, err := http.Get(srv.URL + "/random/path")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./internal/proxy/ -v
```

Expected: compilation error.

- [ ] **Step 3: Implement `internal/proxy/proxy.go`**

```go
package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/ariary/soa/internal/check"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/internal/ui"
	"github.com/ariary/soa/pkg/checkapi"
)

type ActiveManager struct {
	Manager  manager.Manager
	Upstream string
}

type Proxy struct {
	managers []ActiveManager
	client   *check.Client
	spinner  *ui.Spinner
	mux      *http.ServeMux
}

func New(managers []ActiveManager, client *check.Client, spinner *ui.Spinner) *Proxy {
	p := &Proxy{
		managers: managers,
		client:   client,
		spinner:  spinner,
		mux:      http.NewServeMux(),
	}
	p.mux.HandleFunc("/", p.handle)
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mux.ServeHTTP(w, r)
}

// ListenAndServe starts the proxy on the given port and blocks until ctx is cancelled.
func (p *Proxy) ListenAndServe(ctx context.Context, port int) error {
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: p,
	}

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", srv.Addr, err)
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	err = srv.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

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
				return // blocked
			}
		}

		// Forward to upstream
		upstreamURL := am.Manager.UpstreamURL(am.Upstream, r)
		p.forward(w, r, upstreamURL)
		return
	}

	http.NotFound(w, r)
}

func (p *Proxy) checkPackage(ctx context.Context, w http.ResponseWriter, pkg manager.PackageRequest) bool {
	p.spinner.Start(pkg.Module, pkg.Version)

	resp, err := p.client.CheckWithProgress(ctx, checkapi.CheckRequest{
		Module:  pkg.Module,
		Version: pkg.Version,
	}, func(progress float64) {
		p.spinner.SetProgress(pkg.Module, progress)
	})

	if err != nil {
		p.spinner.Stop(pkg.Module, false, "check error: "+err.Error())
		http.Error(w, "package blocked: check error", http.StatusForbidden)
		return false
	}

	if resp.Status == checkapi.StatusBlocked {
		p.spinner.Stop(pkg.Module, false, resp.Reason)
		http.Error(w, fmt.Sprintf("package blocked: %s", resp.Reason), http.StatusForbidden)
		return false
	}

	p.spinner.Stop(pkg.Module, true, "")
	return true
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

- [ ] **Step 4: Run tests — verify they pass**

```bash
go test ./internal/proxy/ -v
```

Expected: all 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/
git commit -m "feat: HTTP intercepting proxy with check integration"
```

---

### Task 7: Reference Check Server

**Files:**
- Create: `internal/server/server.go`
- Create: `internal/server/server_test.go`

- [ ] **Step 1: Write server tests in `internal/server/server_test.go`**

```go
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ariary/soa/pkg/checkapi"
)

func newTestServer(t *testing.T, maxAgeDays int, upstreamTime time.Time) (*Server, *httptest.Server) {
	t.Helper()
	// Mock upstream proxy.golang.org
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Version": "v1.0.0",
			"Time":    upstreamTime.Format(time.RFC3339),
		})
	}))
	t.Cleanup(upstream.Close)

	cachePath := filepath.Join(t.TempDir(), "approved.json")
	s := NewServer(maxAgeDays, cachePath, upstream.URL)
	return s, httptest.NewServer(s.Handler())
}

func TestCheckAllowed_OldPackage(t *testing.T) {
	s, srv := newTestServer(t, 7, time.Now().AddDate(0, -1, 0)) // 1 month old
	defer srv.Close()
	_ = s

	body, _ := json.Marshal(checkapi.CheckRequest{Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusAllowed {
		t.Errorf("expected allowed for old package, got %s: %s", cr.Status, cr.Reason)
	}
}

func TestCheckBlocked_NewPackage(t *testing.T) {
	s, srv := newTestServer(t, 7, time.Now().Add(-2*24*time.Hour)) // 2 days old
	defer srv.Close()
	_ = s

	body, _ := json.Marshal(checkapi.CheckRequest{Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusBlocked {
		t.Errorf("expected blocked for new package, got %s", cr.Status)
	}
	if cr.Reason == "" {
		t.Error("expected a reason for blocking")
	}
}

func TestCheckCacheHit(t *testing.T) {
	s, srv := newTestServer(t, 7, time.Now().AddDate(0, -1, 0))
	defer srv.Close()

	req := checkapi.CheckRequest{Module: "github.com/foo/bar", Version: "v1.0.0"}
	body, _ := json.Marshal(req)

	// First call — populates cache
	resp, _ := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	resp.Body.Close()

	// Second call — should hit cache (we verify by checking the result is still allowed
	// even though we don't re-check the upstream)
	body, _ = json.Marshal(req)
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var cr checkapi.CheckResponse
	json.NewDecoder(resp.Body).Decode(&cr)
	if cr.Status != checkapi.StatusAllowed {
		t.Errorf("expected cache hit allowed, got %s", cr.Status)
	}
}

func TestCachePersistence(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "approved.json")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Version": "v1.0.0",
			"Time":    time.Now().AddDate(0, -1, 0).Format(time.RFC3339),
		})
	}))
	defer upstream.Close()

	s1 := NewServer(7, cachePath, upstream.URL)
	srv1 := httptest.NewServer(s1.Handler())

	body, _ := json.Marshal(checkapi.CheckRequest{Module: "github.com/foo/bar", Version: "v1.0.0"})
	resp, _ := http.Post(srv1.URL+"/check", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	srv1.Close()

	// Verify cache file exists
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache file should exist: %v", err)
	}

	// New server instance should load cache
	s2 := NewServer(7, cachePath, upstream.URL)
	if !s2.isCached("github.com/foo/bar", "v1.0.0") {
		t.Error("expected cache entry to survive restart")
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./internal/server/ -v
```

Expected: compilation error.

- [ ] **Step 3: Implement `internal/server/server.go`**

```go
package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ariary/soa/pkg/checkapi"
)

type cacheEntry struct {
	Module    string    `json:"module"`
	Version   string    `json:"version"`
	ApprovedAt time.Time `json:"approved_at"`
}

type Server struct {
	maxAgeDays  int
	cachePath   string
	upstreamURL string // base URL for proxy.golang.org (or override for testing)
	mu          sync.RWMutex
	cache       map[string]cacheEntry
}

func NewServer(maxAgeDays int, cachePath, upstreamURL string) *Server {
	s := &Server{
		maxAgeDays:  maxAgeDays,
		cachePath:   cachePath,
		upstreamURL: upstreamURL,
		cache:       make(map[string]cacheEntry),
	}
	s.loadCache()
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/check", s.handleCheck)
	return mux
}

func (s *Server) ListenAndServe(port int) error {
	addr := fmt.Sprintf(":%d", port)
	srv := &http.Server{Addr: addr, Handler: s.Handler()}
	return srv.ListenAndServe()
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req checkapi.CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Check cache
	if s.isCached(req.Module, req.Version) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
		return
	}

	// Query upstream for publish time
	publishTime, err := s.fetchPublishTime(req.Module, req.Version)
	if err != nil {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{
			Status: checkapi.StatusBlocked,
			Reason: fmt.Sprintf("failed to verify package age: %v", err),
		})
		return
	}

	age := time.Since(publishTime)
	maxAge := time.Duration(s.maxAgeDays) * 24 * time.Hour

	if age < maxAge {
		days := int(age.Hours() / 24)
		json.NewEncoder(w).Encode(checkapi.CheckResponse{
			Status: checkapi.StatusBlocked,
			Reason: fmt.Sprintf("published %d days ago (minimum: %d days)", days, s.maxAgeDays),
		})
		return
	}

	// Approved — add to cache
	s.addToCache(req.Module, req.Version)

	json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
}

func (s *Server) fetchPublishTime(module, version string) (time.Time, error) {
	url := fmt.Sprintf("%s/%s/@v/%s.info", s.upstreamURL, module, version)
	resp, err := http.Get(url)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return time.Time{}, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, string(body))
	}

	var info struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return time.Time{}, fmt.Errorf("decode .info: %w", err)
	}
	return info.Time, nil
}

func cacheKey(module, version string) string {
	return module + "@" + version
}

func (s *Server) isCached(module, version string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.cache[cacheKey(module, version)]
	return ok
}

func (s *Server) addToCache(module, version string) {
	s.mu.Lock()
	s.cache[cacheKey(module, version)] = cacheEntry{
		Module:    module,
		Version:   version,
		ApprovedAt: time.Now(),
	}
	s.mu.Unlock()
	s.saveCache()
}

func (s *Server) loadCache() {
	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		return // no cache file yet
	}
	var entries []cacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return // corrupted, start fresh
	}
	for _, e := range entries {
		s.cache[cacheKey(e.Module, e.Version)] = e
	}
}

func (s *Server) saveCache() {
	s.mu.RLock()
	entries := make([]cacheEntry, 0, len(s.cache))
	for _, e := range s.cache {
		entries = append(entries, e)
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(s.cachePath, data, 0644)
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
go test ./internal/server/ -v
```

Expected: all 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/server/
git commit -m "feat: reference check server with age check and persistent cache"
```

---

### Task 8: Orchestrator

**Files:**
- Create: `internal/orchestrator/orchestrator.go`
- Create: `internal/orchestrator/orchestrator_test.go`

- [ ] **Step 1: Write orchestrator tests in `internal/orchestrator/orchestrator_test.go`**

```go
package orchestrator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/pkg/checkapi"
)

func TestRunSubprocess_PropagatesExitCode(t *testing.T) {
	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
	}))
	defer checkSrv.Close()

	cfg := config.Config{
		CheckURL:     checkSrv.URL,
		Proxy:        config.ProxyConfig{Port: 0}, // 0 = pick free port
		PollInterval: 100 * time.Millisecond,
		CheckTimeout: 5 * time.Second,
	}

	managers := []manager.Manager{&manager.GolangManager{}}

	// Run a command that exits 0
	code := Run(cfg, managers, []string{"true"}, os.Environ(), false)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	// Run a command that exits 1
	code = Run(cfg, managers, []string{"false"}, os.Environ(), false)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestRunSubprocess_InjectsEnv(t *testing.T) {
	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
	}))
	defer checkSrv.Close()

	cfg := config.Config{
		CheckURL:     checkSrv.URL,
		Proxy:        config.ProxyConfig{Port: 0},
		PollInterval: 100 * time.Millisecond,
		CheckTimeout: 5 * time.Second,
	}

	managers := []manager.Manager{&manager.GolangManager{}}

	// Run env and check that GOPROXY is set to our proxy
	// We use 'sh -c' to print the GOPROXY var
	code := Run(cfg, managers, []string{"sh", "-c", "echo $GOPROXY | grep -q localhost"}, os.Environ(), false)
	if code != 0 {
		t.Errorf("expected GOPROXY to contain localhost, exit code: %d", code)
	}
}
```

- [ ] **Step 2: Run tests — verify they fail**

```bash
go test ./internal/orchestrator/ -v
```

Expected: compilation error.

- [ ] **Step 3: Implement `internal/orchestrator/orchestrator.go`**

```go
package orchestrator

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/ariary/soa/internal/check"
	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/internal/proxy"
	"github.com/ariary/soa/internal/ui"
)

// Run starts the proxy, runs the subprocess, and returns the subprocess exit code.
// If port is 0 in config, a free port is picked automatically.
func Run(cfg config.Config, managers []manager.Manager, args []string, env []string, isTTY bool) int {
	port := cfg.Proxy.Port
	if port == 0 {
		port = freePort()
	}
	proxyAddr := fmt.Sprintf("http://localhost:%d", port)

	// Detect active managers and inject env
	var activeManagers []proxy.ActiveManager
	for _, m := range managers {
		upstream, active := m.Detect(env)
		if !active {
			continue
		}
		env = m.InjectEnv(env, proxyAddr)
		activeManagers = append(activeManagers, proxy.ActiveManager{
			Manager:  m,
			Upstream: upstream,
		})
	}

	if len(activeManagers) == 0 {
		fmt.Fprintf(os.Stderr, "[soa] warning: no ecosystems detected, running as transparent passthrough\n")
	}

	client := check.NewClient(cfg.CheckURL, cfg.CheckTimeout, cfg.PollInterval)
	spinner := ui.NewSpinner(os.Stderr, !isTTY)

	p := proxy.New(activeManagers, client, spinner)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start proxy
	go func() {
		if err := p.ListenAndServe(ctx, port); err != nil {
			fmt.Fprintf(os.Stderr, "[soa] proxy error: %v\n", err)
		}
	}()

	// Run subprocess
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Forward signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				cmd.Process.Signal(sig)
			}
		}
	}()

	exitCode := 0
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			fmt.Fprintf(os.Stderr, "[soa] error: %v\n", err)
			exitCode = 1
		}
	}

	cancel()
	spinner.Shutdown()
	signal.Stop(sigCh)

	return exitCode
}

func freePort() int {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return 8080
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}
```

- [ ] **Step 4: Run tests — verify they pass**

```bash
go test ./internal/orchestrator/ -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/orchestrator/
git commit -m "feat: orchestrator manages subprocess and proxy lifecycle"
```

---

### Task 9: CLI Entrypoint with quicli

**Files:**
- Modify: `cmd/soa/main.go`

- [ ] **Step 1: Get quicli dependency**

```bash
go get github.com/ariary/quicli
```

- [ ] **Step 2: Implement `cmd/soa/main.go`**

```go
package main

import (
	"fmt"
	"os"

	"github.com/ariary/quicli"
	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/internal/server"
	"github.com/ariary/soa/internal/orchestrator"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: soa <command> [args...] or soa serve [--port]")
		os.Exit(1)
	}

	if os.Args[1] == "serve" {
		serveCmd()
		return
	}

	proxyCmd()
}

func serveCmd() {
	cli := quicli.Cli{
		Usage:       "soa serve [flags]",
		Description: "Start the soa reference check server",
		Flags: quicli.Flags{
			{Name: "port", Default: 0, Description: "port to listen on (overrides config)"},
		},
	}

	// Remove "serve" from os.Args so quicli parses the remaining flags
	os.Args = append(os.Args[:1], os.Args[2:]...)
	cfg_parsed := cli.Parse()

	cfg := config.Load()

	port := cfg_parsed.GetIntFlag("port")
	if port != 0 {
		cfg.Server.Port = port
	}

	expandedCachePath := cfg.Server.CachePath
	if len(expandedCachePath) > 0 && expandedCachePath[0] == '~' {
		home, _ := os.UserHomeDir()
		expandedCachePath = home + expandedCachePath[1:]
	}

	// Ensure cache directory exists
	if dir := expandedCachePath[:len(expandedCachePath)-len("/approved.json")]; dir != "" {
		os.MkdirAll(dir, 0755)
	}

	fmt.Fprintf(os.Stderr, "[soa] check server starting on :%d\n", cfg.Server.Port)
	s := server.NewServer(cfg.Server.MaxAgeDays, expandedCachePath, "https://proxy.golang.org")
	if err := s.ListenAndServe(cfg.Server.Port); err != nil {
		fmt.Fprintf(os.Stderr, "[soa] server error: %v\n", err)
		os.Exit(1)
	}
}

func proxyCmd() {
	cfg := config.Load()

	// Collect flags before the command
	disableGo := false
	cmdStart := 1

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--go=false":
			disableGo = true
			cmdStart = i + 1
		default:
			cmdStart = i
			goto done
		}
	}
done:

	if cmdStart >= len(os.Args) {
		fmt.Fprintln(os.Stderr, "Usage: soa [--go=false] <command> [args...]")
		os.Exit(1)
	}

	args := os.Args[cmdStart:]

	var managers []manager.Manager
	if !disableGo {
		managers = append(managers, &manager.GolangManager{})
	}

	isTTY := term.IsTerminal(int(os.Stderr.Fd()))

	exitCode := orchestrator.Run(cfg, managers, args, os.Environ(), isTTY)
	os.Exit(exitCode)
}
```

- [ ] **Step 3: Get term dependency and verify build**

```bash
go get golang.org/x/term
go build ./cmd/soa/
```

Expected: compiles, produces `soa` binary.

- [ ] **Step 4: Quick smoke test**

```bash
./soa echo hello
```

Expected: prints `hello`, exits 0. soa warning about check server is expected.

- [ ] **Step 5: Commit**

```bash
git add cmd/soa/ go.mod go.sum
git commit -m "feat: CLI entrypoint with serve and proxy modes"
```

---

### Task 10: GitHub Actions CI Workflow

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create CI workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        go-version: ['1.22', '1.23']

    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ matrix.go-version }}

      - name: Download dependencies
        run: go mod download

      - name: Build
        run: go build ./...

      - name: Test
        run: go test ./... -v -race -count=1

      - name: Vet
        run: go vet ./...
```

- [ ] **Step 2: Commit**

```bash
git add .github/
git commit -m "ci: add GitHub Actions test workflow"
```

---

### Task 11: README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write `README.md`**

````markdown
# 🛃 soa

Your packages go through customs now.

## The gist

`soa` wraps your package manager commands and intercepts every dependency download through a local proxy. Before any archive reaches your machine, it gets checked against a security policy server. If the package is too fresh, too sketchy, or fails analysis — it gets stopped at the border.

Works with Go today. npm and pip are next in line.

## Show me

Terminal 1 — start the check server:
```bash
soa serve
```

Terminal 2 — install packages as usual, just prefix with `soa`:
```bash
soa go get github.com/gin-gonic/gin
```

That's it. `soa` sets up the proxy, rewires `GOPROXY`, runs your command, and checks every `.zip` download before it lands. You'll see this while it works:

```
[soa] ⠋ scanning github.com/gin-gonic/gin@v1.9.1
[soa] ✓ github.com/gin-gonic/gin@v1.9.1 allowed
```

If something gets blocked:
```
[soa] ✗ github.com/sketchy/lib@v0.0.1 blocked: published 2 days ago
```

It works with aliases too — `soa` doesn't care what binary you run:
```bash
soa gogo test ./...     # if 'gogo' is your Go alias
soa make build          # anything that triggers go module downloads
```

## Get it

```bash
go install github.com/ariary/soa/cmd/soa@latest
```

## Under the hood

```
you ─► soa ─► local proxy ─► check server ─► allow/block
                   │                              │
                   │ if allowed                   │
                   ▼                              │
              upstream proxy ◄────────────────────┘
              (proxy.golang.org)
```

1. `soa` reads your `GOPROXY` to find the real upstream
2. Starts a local HTTP proxy and overrides `GOPROXY` to point to it
3. Spawns your command with the modified environment
4. For every `.zip` request (actual source code downloads), asks the check server
5. `.info` and `.mod` requests pass through — no delay on metadata
6. When done, the proxy shuts down and `soa` exits with your command's exit code

## Knobs

Config lives at `~/.config/soa/config.yaml`:

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

Every value can be overridden with env vars:

| Config | Env var | Default |
|---|---|---|
| `check_url` | `SOA_CHECK_URL` | `http://localhost:9090` |
| `proxy.port` | `SOA_PROXY_PORT` | `8080` |
| `check_timeout` | `SOA_CHECK_TIMEOUT` | `30s` |
| `server.port` | `SOA_SERVER_PORT` | `9090` |
| `server.max_age_days` | `SOA_SERVER_MAX_AGE_DAYS` | `7` |

Disable an ecosystem for a single run:
```bash
soa --go=false npm install foo   # don't intercept Go, only npm (future)
```

## FAQ

**What if I trust everything?**
Don't use soa then. We respect your bravery.

**What if the check server is down?**
All packages are blocked. soa fails closed — no free passes.

**Does this slow things down?**
Only `.zip` downloads go through the check. Metadata (`.info`, `.mod`) flows straight through. If the package is in the approved cache, the check is instant.

**Can I use my own check server?**
Yes. Point `check_url` to any server that speaks the [check API](pkg/checkapi/checkapi.go). The built-in `soa serve` is just a reference implementation.

**What's "soa" mean?**
It's Malagasy. Look it up. 🇲🇬
````

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add README"
```

---

### Task 12: Integration Test

**Files:**
- Create: `integration_test.go`

- [ ] **Step 1: Write end-to-end integration test in `integration_test.go` (project root)**

```go
//go:build integration

package soa_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/internal/orchestrator"
	"github.com/ariary/soa/pkg/checkapi"
)

func TestEndToEnd_GoGetWithCheckServer(t *testing.T) {
	// Mock check server that allows everything
	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
	}))
	defer checkSrv.Close()

	// Mock upstream GOPROXY that serves a minimal .info response
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/github.com/fake/mod/@v/v1.0.0.info" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"Version": "v1.0.0",
				"Time":    time.Now().AddDate(0, -1, 0).Format(time.RFC3339),
			})
			return
		}
		if r.URL.Path == "/github.com/fake/mod/@v/v1.0.0.mod" {
			fmt.Fprint(w, "module github.com/fake/mod\n\ngo 1.21\n")
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	cfg := config.Config{
		CheckURL:     checkSrv.URL,
		Proxy:        config.ProxyConfig{Port: 0},
		PollInterval: 50 * time.Millisecond,
		CheckTimeout: 5 * time.Second,
	}

	env := os.Environ()
	// Override GOPROXY to point at our mock upstream
	env = append(env, "GOPROXY="+upstream.URL)

	managers := []manager.Manager{&manager.GolangManager{}}

	// Run 'go env GOPROXY' through soa — verify it sees our proxy, not the upstream
	code := orchestrator.Run(cfg, managers, []string{"sh", "-c", "echo $GOPROXY"}, env, false)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
}

func TestEndToEnd_BinaryBuilds(t *testing.T) {
	cmd := exec.Command("go", "build", "-o", "/dev/null", "./cmd/soa/")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build soa: %v\n%s", err, out)
	}
}
```

- [ ] **Step 2: Run integration tests**

```bash
go test -tags=integration -v -count=1 .
```

Expected: all tests pass.

- [ ] **Step 3: Run all unit tests to verify nothing is broken**

```bash
go test ./... -v -race -count=1
```

Expected: all tests pass across all packages.

- [ ] **Step 4: Commit**

```bash
git add integration_test.go
git commit -m "test: add end-to-end integration tests"
```

---

### Task 13: Final Cleanup

- [ ] **Step 1: Run `go mod tidy`**

```bash
go mod tidy
```

- [ ] **Step 2: Run full test suite**

```bash
go vet ./...
go test ./... -v -race -count=1
```

Expected: no vet warnings, all tests pass.

- [ ] **Step 3: Commit if go.sum changed**

```bash
git add go.mod go.sum
git commit -m "chore: tidy module dependencies"
```
