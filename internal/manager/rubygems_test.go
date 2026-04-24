package manager

import (
	"net/http"
	"strings"
	"testing"
)

func TestRubyGemsDetect_FromEnv(t *testing.T) {
	env := []string{"HOME=/home/user", "GEM_HOST=https://gems.company.com"}
	m := &RubyGemsManager{}
	upstream, active := m.Detect(env)
	if !active {
		t.Fatal("expected active when GEM_HOST is set")
	}
	if upstream != "https://gems.company.com" {
		t.Errorf("expected upstream from env, got %s", upstream)
	}
}

func TestRubyGemsDetect_NoEnv(t *testing.T) {
	env := []string{"HOME=/home/user"}
	m := &RubyGemsManager{}
	upstream, active := m.Detect(env)
	if !active {
		t.Fatal("expected active with default")
	}
	if upstream != "https://rubygems.org" {
		t.Errorf("expected default upstream, got %s", upstream)
	}
}

func TestRubyGemsInjectEnv(t *testing.T) {
	env := []string{"HOME=/home/user", "GEM_HOST=https://rubygems.org"}
	m := &RubyGemsManager{}
	injected := m.InjectEnv(env, "http://localhost:8080")

	found := map[string]string{}
	for _, e := range injected {
		parts := strings.SplitN(e, "=", 2)
		found[parts[0]] = parts[1]
	}

	if found["GEM_HOST"] != "http://localhost:8080/rubygems" {
		t.Errorf("GEM_HOST not overridden, got %s", found["GEM_HOST"])
	}
}

func TestRubyGemsMatch(t *testing.T) {
	m := &RubyGemsManager{}
	tests := []struct {
		path  string
		match bool
	}{
		{"/rubygems/gems/rails-7.1.3.gem", true},
		{"/rubygems/gems/rack-test-2.1.0.gem", true},
		{"/rubygems/specs.4.8.gz", true},
		{"/rubygems/api/v1/gems/rails.json", true},
		{"/npm/lodash/-/lodash-4.17.21.tgz", false},
		{"/github.com/foo/@v/v1.0.0.zip", false},
	}
	for _, tt := range tests {
		r, _ := http.NewRequest("GET", "http://localhost"+tt.path, nil)
		if got := m.Match(r); got != tt.match {
			t.Errorf("Match(%s) = %v, want %v", tt.path, got, tt.match)
		}
	}
}

func TestRubyGemsParse_GemDownload(t *testing.T) {
	m := &RubyGemsManager{}
	tests := []struct {
		path     string
		module   string
		version  string
		download bool
	}{
		{"/rubygems/gems/rails-7.1.3.gem", "rails", "7.1.3", true},
		{"/rubygems/gems/rack-test-2.1.0.gem", "rack-test", "2.1.0", true},
		{"/rubygems/gems/nokogiri-1.16.0-x86_64-linux.gem", "nokogiri", "1.16.0-x86_64-linux", true},
	}
	for _, tt := range tests {
		r, _ := http.NewRequest("GET", "http://localhost"+tt.path, nil)
		pkg, err := m.Parse(r)
		if err != nil {
			t.Errorf("Parse(%s) error: %v", tt.path, err)
			continue
		}
		if pkg.Ecosystem != "rubygems" {
			t.Errorf("Parse(%s).Ecosystem = %s, want rubygems", tt.path, pkg.Ecosystem)
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

func TestRubyGemsParse_Metadata(t *testing.T) {
	m := &RubyGemsManager{}
	r, _ := http.NewRequest("GET", "http://localhost/rubygems/specs.4.8.gz", nil)
	pkg, err := m.Parse(r)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if pkg.Download {
		t.Error("specs request should not be a download")
	}
}

func TestRubyGemsUpstreamURL(t *testing.T) {
	m := &RubyGemsManager{}
	r, _ := http.NewRequest("GET", "http://localhost/rubygems/gems/rails-7.1.3.gem", nil)
	got := m.UpstreamURL("https://rubygems.org", r)
	want := "https://rubygems.org/gems/rails-7.1.3.gem"
	if got != want {
		t.Errorf("UpstreamURL = %s, want %s", got, want)
	}
}
