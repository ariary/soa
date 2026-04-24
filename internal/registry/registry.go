package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var client = &http.Client{Timeout: 30 * time.Second}

func FetchPublishTime(upstreams map[string]string, ecosystem, module, version string) (time.Time, error) {
	base, ok := upstreams[ecosystem]
	if !ok {
		return time.Time{}, fmt.Errorf("unknown ecosystem: %s", ecosystem)
	}
	base = strings.TrimRight(base, "/")

	switch ecosystem {
	case "go":
		return fetchGoPublishTime(base, module, version)
	case "npm":
		return fetchNpmPublishTime(base, module, version)
	case "pip":
		return fetchPipPublishTime(base, module, version)
	case "rubygems":
		return fetchRubyGemsPublishTime(base, module, version)
	default:
		return time.Time{}, fmt.Errorf("unknown ecosystem: %s", ecosystem)
	}
}

func FetchVersionList(upstreams map[string]string, ecosystem, module string) ([]string, error) {
	base, ok := upstreams[ecosystem]
	if !ok {
		return nil, fmt.Errorf("unknown ecosystem: %s", ecosystem)
	}
	base = strings.TrimRight(base, "/")

	switch ecosystem {
	case "go":
		return fetchGoVersionList(base, module)
	case "npm":
		return fetchNpmVersionList(base, module)
	case "pip":
		return fetchPipVersionList(base, module)
	case "rubygems":
		return fetchRubyGemsVersionList(base, module)
	default:
		return nil, fmt.Errorf("unknown ecosystem: %s", ecosystem)
	}
}

func fetchGoPublishTime(base, module, version string) (time.Time, error) {
	url := fmt.Sprintf("%s/%s/@v/%s.info", base, module, version)
	body, err := httpGet(url)
	if err != nil {
		return time.Time{}, err
	}
	var info struct {
		Time time.Time `json:"Time"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return time.Time{}, fmt.Errorf("decode .info: %w", err)
	}
	return info.Time, nil
}

func fetchGoVersionList(base, module string) ([]string, error) {
	url := fmt.Sprintf("%s/%s/@v/list", base, module)
	body, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(body))
	if text == "" {
		return nil, nil
	}
	return strings.Split(text, "\n"), nil
}

func fetchNpmPublishTime(base, module, version string) (time.Time, error) {
	url := fmt.Sprintf("%s/%s", base, module)
	body, err := httpGet(url)
	if err != nil {
		return time.Time{}, err
	}
	var pkg struct {
		Time map[string]string `json:"time"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return time.Time{}, fmt.Errorf("decode npm metadata: %w", err)
	}
	ts, ok := pkg.Time[version]
	if !ok {
		return time.Time{}, fmt.Errorf("version %s not found in time map", version)
	}
	return time.Parse(time.RFC3339, ts)
}

func fetchNpmVersionList(base, module string) ([]string, error) {
	url := fmt.Sprintf("%s/%s", base, module)
	body, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return nil, fmt.Errorf("decode npm metadata: %w", err)
	}
	versions := make([]string, 0, len(pkg.Versions))
	for v := range pkg.Versions {
		versions = append(versions, v)
	}
	return versions, nil
}

func fetchPipPublishTime(base, module, version string) (time.Time, error) {
	url := fmt.Sprintf("%s/pypi/%s/%s/json", base, module, version)
	body, err := httpGet(url)
	if err != nil {
		return time.Time{}, err
	}
	var pkg struct {
		URLs []struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"urls"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return time.Time{}, fmt.Errorf("decode PyPI metadata: %w", err)
	}
	if len(pkg.URLs) == 0 {
		return time.Time{}, fmt.Errorf("no URLs in PyPI response for %s@%s", module, version)
	}
	return time.Parse(time.RFC3339, pkg.URLs[0].UploadTime)
}

func fetchPipVersionList(base, module string) ([]string, error) {
	url := fmt.Sprintf("%s/pypi/%s/json", base, module)
	body, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Releases map[string]json.RawMessage `json:"releases"`
	}
	if err := json.Unmarshal(body, &pkg); err != nil {
		return nil, fmt.Errorf("decode PyPI metadata: %w", err)
	}
	versions := make([]string, 0, len(pkg.Releases))
	for v := range pkg.Releases {
		versions = append(versions, v)
	}
	return versions, nil
}

func fetchRubyGemsPublishTime(base, module, version string) (time.Time, error) {
	url := fmt.Sprintf("%s/api/v2/rubygems/%s/versions/%s.json", base, module, version)
	body, err := httpGet(url)
	if err != nil {
		return time.Time{}, err
	}
	var gem struct {
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(body, &gem); err != nil {
		return time.Time{}, fmt.Errorf("decode RubyGems metadata: %w", err)
	}
	return time.Parse(time.RFC3339, gem.CreatedAt)
}

func fetchRubyGemsVersionList(base, module string) ([]string, error) {
	url := fmt.Sprintf("%s/api/v1/versions/%s.json", base, module)
	body, err := httpGet(url)
	if err != nil {
		return nil, err
	}
	var gems []struct {
		Number string `json:"number"`
	}
	if err := json.Unmarshal(body, &gems); err != nil {
		return nil, fmt.Errorf("decode RubyGems versions: %w", err)
	}
	versions := make([]string, 0, len(gems))
	for _, g := range gems {
		versions = append(versions, g.Number)
	}
	return versions, nil
}

func httpGet(url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}
