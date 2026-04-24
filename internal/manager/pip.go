package manager

import (
	"bytes"
	"net/http"
	"path"
	"strings"
)

type PipManager struct{}

func (p *PipManager) Name() string { return "pip" }

func (p *PipManager) Detect(env []string) (string, bool) {
	for _, e := range env {
		if val, ok := strings.CutPrefix(e, "PIP_INDEX_URL="); ok && val != "" {
			base := strings.TrimRight(val, "/")
			base = strings.TrimSuffix(base, "/simple")
			return base, true
		}
	}
	return "https://pypi.org", true
}

func (p *PipManager) InjectEnv(env []string, proxyAddr string) []string {
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		key := strings.SplitN(e, "=", 2)[0]
		if key == "PIP_INDEX_URL" {
			continue
		}
		filtered = append(filtered, e)
	}
	return append(filtered, "PIP_INDEX_URL="+proxyAddr+"/pypi/simple/")
}

func (p *PipManager) Match(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/pypi/")
}

func (p *PipManager) Parse(r *http.Request) (PackageRequest, error) {
	urlPath := strings.TrimPrefix(r.URL.Path, "/pypi/")

	if strings.HasPrefix(urlPath, "packages/") {
		filename := path.Base(urlPath)
		name, version := parsePipFilename(filename)
		return PackageRequest{
			Ecosystem: "pip",
			Module:    name,
			Version:   version,
			Type:      "package",
			Download:  true,
		}, nil
	}

	if strings.HasPrefix(urlPath, "simple/") {
		pkg := strings.TrimPrefix(urlPath, "simple/")
		pkg = strings.Trim(pkg, "/")
		return PackageRequest{
			Ecosystem: "pip",
			Module:    pkg,
			Type:      "index",
		}, nil
	}

	return PackageRequest{Ecosystem: "pip", Module: urlPath, Type: "metadata"}, nil
}

func parsePipFilename(filename string) (name, version string) {
	if strings.HasSuffix(filename, ".whl") {
		parts := strings.SplitN(strings.TrimSuffix(filename, ".whl"), "-", 3)
		if len(parts) >= 2 {
			return parts[0], parts[1]
		}
	}
	if strings.HasSuffix(filename, ".tar.gz") {
		s := strings.TrimSuffix(filename, ".tar.gz")
		for i := 0; i < len(s); i++ {
			if s[i] == '-' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
				return s[:i], s[i+1:]
			}
		}
	}
	return filename, ""
}

func (p *PipManager) UpstreamURL(upstream string, r *http.Request) string {
	urlPath := strings.TrimPrefix(r.URL.Path, "/pypi/")

	if strings.HasPrefix(urlPath, "packages/") {
		return "https://files.pythonhosted.org/" + urlPath
	}

	return strings.TrimRight(upstream, "/") + "/" + urlPath
}

func (p *PipManager) RewriteResponse(r *http.Request, body []byte, proxyAddr string) []byte {
	if !strings.HasPrefix(r.URL.Path, "/pypi/simple/") {
		return body
	}
	return bytes.ReplaceAll(body,
		[]byte("https://files.pythonhosted.org/packages/"),
		[]byte(proxyAddr+"/pypi/packages/"),
	)
}
