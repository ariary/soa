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

// ResponseRewriter is an optional interface that managers can implement to
// transform upstream response bodies before sending them to the client.
// Used by PipManager to rewrite download URLs in the PyPI simple index.
type ResponseRewriter interface {
	RewriteResponse(r *http.Request, body []byte, proxyAddr string) []byte
}
