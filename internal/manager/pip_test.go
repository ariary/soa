package manager

import (
	"net/http"
	"strings"
	"testing"
)

func TestPipDetect_FromEnv(t *testing.T) {
	env := []string{"HOME=/home/user", "PIP_INDEX_URL=https://pypi.company.com/simple/"}
	m := &PipManager{}
	upstream, active := m.Detect(env)
	if !active {
		t.Fatal("expected active when PIP_INDEX_URL is set")
	}
	if upstream != "https://pypi.company.com" {
		t.Errorf("expected upstream from env (base URL), got %s", upstream)
	}
}

func TestPipDetect_NoEnv(t *testing.T) {
	env := []string{"HOME=/home/user"}
	m := &PipManager{}
	upstream, active := m.Detect(env)
	if !active {
		t.Fatal("expected active with default")
	}
	if upstream != "https://pypi.org" {
		t.Errorf("expected default upstream, got %s", upstream)
	}
}

func TestPipInjectEnv(t *testing.T) {
	env := []string{"HOME=/home/user", "PIP_INDEX_URL=https://pypi.org/simple/"}
	m := &PipManager{}
	injected := m.InjectEnv(env, "http://localhost:8080")

	found := map[string]string{}
	for _, e := range injected {
		parts := strings.SplitN(e, "=", 2)
		found[parts[0]] = parts[1]
	}

	if found["PIP_INDEX_URL"] != "http://localhost:8080/pypi/simple/" {
		t.Errorf("PIP_INDEX_URL not overridden, got %s", found["PIP_INDEX_URL"])
	}
}

func TestPipMatch(t *testing.T) {
	m := &PipManager{}
	tests := []struct {
		path  string
		match bool
	}{
		{"/pypi/simple/requests/", true},
		{"/pypi/packages/ab/cd/requests-2.31.0.tar.gz", true},
		{"/pypi/packages/ab/cd/requests-2.31.0-py3-none-any.whl", true},
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

func TestPipParse_Download(t *testing.T) {
	m := &PipManager{}
	tests := []struct {
		path     string
		module   string
		version  string
		download bool
	}{
		{"/pypi/packages/ab/cd/requests-2.31.0.tar.gz", "requests", "2.31.0", true},
		{"/pypi/packages/ab/cd/requests-2.31.0-py3-none-any.whl", "requests", "2.31.0", true},
		{"/pypi/packages/ab/cd/my_package-1.0.0.tar.gz", "my_package", "1.0.0", true},
	}
	for _, tt := range tests {
		r, _ := http.NewRequest("GET", "http://localhost"+tt.path, nil)
		pkg, err := m.Parse(r)
		if err != nil {
			t.Errorf("Parse(%s) error: %v", tt.path, err)
			continue
		}
		if pkg.Ecosystem != "pip" {
			t.Errorf("Parse(%s).Ecosystem = %s, want pip", tt.path, pkg.Ecosystem)
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

func TestPipParse_SimpleIndex(t *testing.T) {
	m := &PipManager{}
	r, _ := http.NewRequest("GET", "http://localhost/pypi/simple/requests/", nil)
	pkg, err := m.Parse(r)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if pkg.Download {
		t.Error("simple index request should not be a download")
	}
	if pkg.Module != "requests" {
		t.Errorf("Module = %s, want requests", pkg.Module)
	}
}

func TestPipRewriteResponse(t *testing.T) {
	m := &PipManager{}

	body := []byte(`<a href="https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0.tar.gz#sha256=abc">requests-2.31.0.tar.gz</a>`)
	r, _ := http.NewRequest("GET", "http://localhost/pypi/simple/requests/", nil)

	rewritten := m.RewriteResponse(r, body, "http://localhost:8080")

	expected := `<a href="http://localhost:8080/pypi/packages/ab/cd/requests-2.31.0.tar.gz#sha256=abc">requests-2.31.0.tar.gz</a>`
	if string(rewritten) != expected {
		t.Errorf("rewrite failed:\ngot:  %s\nwant: %s", string(rewritten), expected)
	}
}

func TestPipRewriteResponse_NonIndex(t *testing.T) {
	m := &PipManager{}

	body := []byte("some binary content")
	r, _ := http.NewRequest("GET", "http://localhost/pypi/packages/ab/cd/requests-2.31.0.tar.gz", nil)

	rewritten := m.RewriteResponse(r, body, "http://localhost:8080")

	if string(rewritten) != string(body) {
		t.Error("non-index response should not be rewritten")
	}
}

func TestPipUpstreamURL(t *testing.T) {
	m := &PipManager{}
	tests := []struct {
		path string
		want string
	}{
		{"/pypi/simple/requests/", "https://pypi.org/simple/requests/"},
		{"/pypi/packages/ab/cd/requests-2.31.0.tar.gz", "https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0.tar.gz"},
	}
	for _, tt := range tests {
		r, _ := http.NewRequest("GET", "http://localhost"+tt.path, nil)
		got := m.UpstreamURL("https://pypi.org", r)
		if got != tt.want {
			t.Errorf("UpstreamURL(%s) = %s, want %s", tt.path, got, tt.want)
		}
	}
}
