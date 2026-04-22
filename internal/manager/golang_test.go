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

	if found["GOPROXY"] != "http://localhost:8080,direct" {
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

func TestGolangParseUpstreamChain_CommaSeparated(t *testing.T) {
	gm := &GolangManager{}
	entries := gm.ParseUpstreamChain("https://proxy1.example,https://proxy2.example,direct")
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].URL != "https://proxy1.example" || !entries[0].FallbackOnNotFound || entries[0].FallbackOnError {
		t.Errorf("entry 0: %+v", entries[0])
	}
	if entries[1].URL != "https://proxy2.example" || !entries[1].FallbackOnNotFound {
		t.Errorf("entry 1: %+v", entries[1])
	}
	if entries[2].URL != "direct" || !entries[2].IsDirect {
		t.Errorf("entry 2: %+v", entries[2])
	}
}

func TestGolangParseUpstreamChain_PipeSeparated(t *testing.T) {
	gm := &GolangManager{}
	entries := gm.ParseUpstreamChain("https://proxy1.example|https://proxy2.example")
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if !entries[0].FallbackOnError {
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
	if !entries[0].FallbackOnError {
		t.Errorf("entry 0 should fallback on error (pipe): %+v", entries[0])
	}
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
