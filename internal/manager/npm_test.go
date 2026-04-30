package manager

import (
	"net/http"
	"strings"
	"testing"
)

func TestNpmDetect_FromEnv(t *testing.T) {
	env := []string{"HOME=/home/user", "npm_config_registry=https://registry.company.com"}
	m := &NpmManager{}
	upstream, active := m.Detect(env)
	if !active {
		t.Fatal("expected active when npm_config_registry is set")
	}
	if upstream != "https://registry.company.com" {
		t.Errorf("expected upstream from env, got %s", upstream)
	}
}

func TestNpmDetect_NoEnv(t *testing.T) {
	env := []string{"HOME=/home/user"}
	m := &NpmManager{}
	upstream, active := m.Detect(env)
	if !active {
		t.Fatal("expected active with default registry")
	}
	if upstream != "https://registry.npmjs.org" {
		t.Errorf("expected default upstream, got %s", upstream)
	}
}

func TestNpmInjectEnv(t *testing.T) {
	env := []string{"HOME=/home/user", "npm_config_registry=https://registry.npmjs.org"}
	m := &NpmManager{}
	injected := m.InjectEnv(env, "http://localhost:8080")

	found := map[string]string{}
	for _, e := range injected {
		parts := strings.SplitN(e, "=", 2)
		found[parts[0]] = parts[1]
	}

	if found["npm_config_registry"] != "http://localhost:8080/npm" {
		t.Errorf("npm_config_registry not overridden, got %s", found["npm_config_registry"])
	}
	if found["HOME"] != "/home/user" {
		t.Errorf("HOME should be preserved, got %q", found["HOME"])
	}
}

func TestNpmMatch(t *testing.T) {
	m := &NpmManager{}
	tests := []struct {
		path  string
		match bool
	}{
		{"/npm/lodash/-/lodash-4.17.21.tgz", true},
		{"/npm/@babel/core/-/core-7.24.0.tgz", true},
		{"/npm/express", true},
		{"/npm/@types/node", true},
		{"/github.com/foo/bar/@v/v1.0.0.zip", false},
		{"/some/random/path", false},
	}
	for _, tt := range tests {
		r, _ := http.NewRequest("GET", "http://localhost"+tt.path, nil)
		if got := m.Match(r); got != tt.match {
			t.Errorf("Match(%s) = %v, want %v", tt.path, got, tt.match)
		}
	}
}

func TestNpmParse_Tarball(t *testing.T) {
	m := &NpmManager{}
	tests := []struct {
		path     string
		module   string
		version  string
		download bool
	}{
		{"/npm/lodash/-/lodash-4.17.21.tgz", "lodash", "4.17.21", true},
		{"/npm/@babel/core/-/core-7.24.0.tgz", "@babel/core", "7.24.0", true},
		{"/npm/is-odd/-/is-odd-1.0.0.tgz", "is-odd", "1.0.0", true},
	}
	for _, tt := range tests {
		r, _ := http.NewRequest("GET", "http://localhost"+tt.path, nil)
		pkg, err := m.Parse(r)
		if err != nil {
			t.Errorf("Parse(%s) error: %v", tt.path, err)
			continue
		}
		if pkg.Ecosystem != "npm" {
			t.Errorf("Parse(%s).Ecosystem = %s, want npm", tt.path, pkg.Ecosystem)
		}
		if pkg.Module != tt.module {
			t.Errorf("Parse(%s).Module = %s, want %s", tt.path, pkg.Module, tt.module)
		}
		if pkg.Version != tt.version {
			t.Errorf("Parse(%s).Version = %s, want %s", tt.path, pkg.Version, tt.version)
		}
		if pkg.Download != tt.download {
			t.Errorf("Parse(%s).Download = %v, want %v", tt.path, pkg.Download, tt.download)
		}
	}
}

func TestNpmParse_Metadata(t *testing.T) {
	m := &NpmManager{}
	tests := []struct {
		path   string
		module string
	}{
		{"/npm/express", "express"},
		{"/npm/@types/node", "@types/node"},
	}
	for _, tt := range tests {
		r, _ := http.NewRequest("GET", "http://localhost"+tt.path, nil)
		pkg, err := m.Parse(r)
		if err != nil {
			t.Errorf("Parse(%s) error: %v", tt.path, err)
			continue
		}
		if pkg.Module != tt.module {
			t.Errorf("Parse(%s).Module = %s, want %s", tt.path, pkg.Module, tt.module)
		}
		if pkg.Download {
			t.Errorf("Parse(%s).Download should be false for metadata", tt.path)
		}
	}
}

func TestNpmUpstreamURL(t *testing.T) {
	m := &NpmManager{}
	tests := []struct {
		path string
		want string
	}{
		{"/npm/lodash/-/lodash-4.17.21.tgz", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
		{"/npm/@babel/core/-/core-7.24.0.tgz", "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz"},
		{"/npm/express", "https://registry.npmjs.org/express"},
	}
	for _, tt := range tests {
		r, _ := http.NewRequest("GET", "http://localhost"+tt.path, nil)
		got := m.UpstreamURL("https://registry.npmjs.org", r)
		if got != tt.want {
			t.Errorf("UpstreamURL(%s) = %s, want %s", tt.path, got, tt.want)
		}
	}
}

func TestNpmDetect_EmptyValue(t *testing.T) {
	// npm_config_registry= (empty value) should fall through to default.
	env := []string{"HOME=/home/user", "npm_config_registry=", "PATH=/usr/bin"}
	m := &NpmManager{}
	upstream, active := m.Detect(env)
	if !active {
		t.Fatal("expected active with default registry")
	}
	if upstream != "https://registry.npmjs.org" {
		t.Errorf("expected default upstream when npm_config_registry is empty, got %s", upstream)
	}
}

func TestNpmParse_TarballAtStart(t *testing.T) {
	// Path where "/-/" is at position 0 in the trimmed path.
	// After trimming "/npm/", path becomes "/-/foo-1.0.0.tgz"
	// idx of "/-/" is 0, which is >= 0, so it enters the tarball branch.
	// pkgName = path[:0] = ""
	m := &NpmManager{}
	r, _ := http.NewRequest("GET", "http://localhost/npm//-/foo-1.0.0.tgz", nil)
	pkg, err := m.Parse(r)
	if err != nil {
		t.Fatalf("Parse should not error, got: %v", err)
	}
	// When idx == 0, pkgName is empty string
	if pkg.Module != "" {
		t.Errorf("expected empty module when /-/ is at start, got %q", pkg.Module)
	}
	if !pkg.Download {
		t.Error("expected download=true for tarball path")
	}
	if pkg.Type != "tgz" {
		t.Errorf("expected type tgz, got %s", pkg.Type)
	}
}
