package manager

import (
	"net/http"
	"strings"
)

type RubyGemsManager struct{}

func (g *RubyGemsManager) Name() string { return "rubygems" }

func (g *RubyGemsManager) Detect(env []string) (string, bool) {
	for _, e := range env {
		if val, ok := strings.CutPrefix(e, "GEM_HOST="); ok && val != "" {
			return strings.TrimRight(val, "/"), true
		}
	}
	return "https://rubygems.org", true
}

func (g *RubyGemsManager) InjectEnv(env []string, proxyAddr string) []string {
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		key := strings.SplitN(e, "=", 2)[0]
		if key == "GEM_HOST" {
			continue
		}
		filtered = append(filtered, e)
	}
	return append(filtered, "GEM_HOST="+proxyAddr+"/rubygems")
}

func (g *RubyGemsManager) Match(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/rubygems/")
}

func (g *RubyGemsManager) Parse(r *http.Request) (PackageRequest, error) {
	path := strings.TrimPrefix(r.URL.Path, "/rubygems/")

	if strings.HasPrefix(path, "gems/") && strings.HasSuffix(path, ".gem") {
		filename := strings.TrimPrefix(path, "gems/")
		name, version := parseGemFilename(filename)
		return PackageRequest{
			Ecosystem: "rubygems",
			Module:    name,
			Version:   version,
			Type:      "gem",
			Download:  true,
		}, nil
	}

	return PackageRequest{
		Ecosystem: "rubygems",
		Module:    path,
		Type:      "metadata",
	}, nil
}

// parseGemFilename extracts name and version from a gem filename like
// "rack-test-2.1.0.gem". Finds the last hyphen followed by a digit.
func parseGemFilename(filename string) (name, version string) {
	s := strings.TrimSuffix(filename, ".gem")
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '-' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}

func (g *RubyGemsManager) UpstreamURL(upstream string, r *http.Request) string {
	path := strings.TrimPrefix(r.URL.Path, "/rubygems")
	return strings.TrimRight(upstream, "/") + path
}
