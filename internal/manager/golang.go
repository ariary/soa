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
func (g *GolangManager) ParseUpstreamChain(goproxy string) []ProxyEntry {
	if goproxy == "off" {
		return []ProxyEntry{{IsOff: true}}
	}

	var entries []ProxyEntry
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
