package manager

import "net/http"

type PackageRequest struct {
	Module  string
	Version string
	Type    string // "info", "mod", "zip", "list", "latest"
}

func (p PackageRequest) NeedsCheck() bool {
	return p.Type == "zip"
}

// ProxyEntry represents one entry in a GOPROXY chain.
type ProxyEntry struct {
	URL                string
	FallbackOnNotFound bool // comma separator: try next on 404/410
	FallbackOnError    bool // pipe separator: try next on any error
	IsDirect           bool // "direct" keyword
	IsOff              bool // "off" keyword
}

type Manager interface {
	Name() string
	Detect(env []string) (upstream string, active bool)
	InjectEnv(env []string, proxyAddr string) []string
	Match(r *http.Request) bool
	Parse(r *http.Request) (PackageRequest, error)
	UpstreamURL(upstream string, r *http.Request) string
}
