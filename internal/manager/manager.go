package manager

import "net/http"

type PackageRequest struct {
	Ecosystem string // "go", "npm", "pip", "rubygems"
	Module    string
	Version   string
	Type      string // ecosystem-specific type
	Download  bool   // true if this is a package download (needs check)
}

func (p PackageRequest) NeedsCheck() bool {
	return p.Download
}

type Manager interface {
	Name() string
	Detect(env []string) (upstream string, active bool)
	InjectEnv(env []string, proxyAddr string) []string
	Match(r *http.Request) bool
	Parse(r *http.Request) (PackageRequest, error)
	UpstreamURL(upstream string, r *http.Request) string
}
