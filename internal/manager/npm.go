package manager

import (
	"fmt"
	"net/http"
	"strings"
)

type NpmManager struct{}

func (n *NpmManager) Name() string { return "npm" }

func (n *NpmManager) Detect(env []string) (string, bool) {
	for _, e := range env {
		if val, ok := strings.CutPrefix(e, "npm_config_registry="); ok && val != "" {
			return strings.TrimRight(val, "/"), true
		}
	}
	return "https://registry.npmjs.org", true
}

func (n *NpmManager) InjectEnv(env []string, proxyAddr string) []string {
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		key := strings.SplitN(e, "=", 2)[0]
		if key == "npm_config_registry" {
			continue
		}
		filtered = append(filtered, e)
	}
	return append(filtered, "npm_config_registry="+proxyAddr+"/npm")
}

func (n *NpmManager) Match(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/npm/")
}

func (n *NpmManager) Parse(r *http.Request) (PackageRequest, error) {
	path := strings.TrimPrefix(r.URL.Path, "/npm/")
	if path == "" {
		return PackageRequest{}, fmt.Errorf("empty npm path")
	}

	// Tarball download: path contains /-/ and ends with .tgz
	if idx := strings.Index(path, "/-/"); idx >= 0 && strings.HasSuffix(path, ".tgz") {
		pkgName := path[:idx]
		tarball := path[idx+3:] // after "/-/"

		shortName := pkgName
		if strings.HasPrefix(pkgName, "@") {
			if slashIdx := strings.LastIndex(pkgName, "/"); slashIdx >= 0 {
				shortName = pkgName[slashIdx+1:]
			}
		}

		version := strings.TrimSuffix(tarball, ".tgz")
		version = strings.TrimPrefix(version, shortName+"-")

		return PackageRequest{
			Ecosystem: "npm",
			Module:    pkgName,
			Version:   version,
			Type:      "tgz",
			Download:  true,
		}, nil
	}

	// Metadata request
	return PackageRequest{
		Ecosystem: "npm",
		Module:    path,
		Type:      "metadata",
	}, nil
}

func (n *NpmManager) UpstreamURL(upstream string, r *http.Request) string {
	path := strings.TrimPrefix(r.URL.Path, "/npm")
	return strings.TrimRight(upstream, "/") + path
}
