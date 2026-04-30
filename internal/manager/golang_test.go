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
	if found["HOME"] != "/home/user" {
		t.Errorf("HOME should be preserved, got %q", found["HOME"])
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

func TestGolangParse_SetsEcosystemAndDownload(t *testing.T) {
	gm := &GolangManager{}
	tests := []struct {
		path     string
		eco      string
		download bool
	}{
		{"/github.com/foo/bar/@v/v1.0.0.zip", "go", true},
		{"/github.com/foo/bar/@v/v1.0.0.info", "go", false},
		{"/github.com/foo/bar/@v/v1.0.0.mod", "go", false},
		{"/github.com/foo/bar/@v/list", "go", false},
	}
	for _, tt := range tests {
		r, _ := http.NewRequest("GET", "http://localhost"+tt.path, nil)
		pkg, err := gm.Parse(r)
		if err != nil {
			t.Errorf("Parse(%s) error: %v", tt.path, err)
			continue
		}
		if pkg.Ecosystem != tt.eco {
			t.Errorf("Parse(%s).Ecosystem = %s, want %s", tt.path, pkg.Ecosystem, tt.eco)
		}
		if pkg.Download != tt.download {
			t.Errorf("Parse(%s).Download = %v, want %v", tt.path, pkg.Download, tt.download)
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

func TestGolangDetect_EmptyValue(t *testing.T) {
	// GOPROXY= (empty value after '=') should NOT be detected; fall through to default.
	env := []string{"HOME=/home/user", "GOPROXY=", "PATH=/usr/bin"}
	gm := &GolangManager{}
	upstream, active := gm.Detect(env)
	if !active {
		t.Fatal("expected active with default GOPROXY")
	}
	if upstream != "https://proxy.golang.org,direct" {
		t.Errorf("expected default upstream when GOPROXY is empty, got %s", upstream)
	}
}

func TestGolangParse_NoDotInRest(t *testing.T) {
	// A request like /@v/list has no dot in rest, and should be handled by the "list" check.
	// A request like /@v/something (no dot, not "list") should return an error.
	gm := &GolangManager{}

	// "list" case: no dot, but rest == "list" -> OK
	r, _ := http.NewRequest("GET", "http://localhost/github.com/foo/bar/@v/list", nil)
	pkg, err := gm.Parse(r)
	if err != nil {
		t.Fatalf("Parse list should succeed, got error: %v", err)
	}
	if pkg.Type != "list" {
		t.Errorf("expected type list, got %s", pkg.Type)
	}

	// Non-list, no dot: should error (lastDot < 0)
	r2, _ := http.NewRequest("GET", "http://localhost/github.com/foo/bar/@v/nodot", nil)
	_, err = gm.Parse(r2)
	if err == nil {
		t.Fatal("expected error when rest has no dot and is not 'list'")
	}
}
