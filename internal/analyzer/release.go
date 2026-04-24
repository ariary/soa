package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ariary/soa/internal/analyzer/prompt"
	"github.com/ariary/soa/internal/github"
	"github.com/ariary/soa/internal/provider"
)

// ReleaseAnalyzer uses an LLM to analyze release metadata (registry info and
// optional GitHub data) for supply-chain security threats.
type ReleaseAnalyzer struct {
	llm       provider.Provider
	gh        *github.Client
	upstreams map[string]string
	client    *http.Client
}

// NewReleaseAnalyzer creates a ReleaseAnalyzer. A GitHub client is created only
// if githubBaseURL or githubToken is non-empty.
func NewReleaseAnalyzer(llm provider.Provider, githubBaseURL, githubToken string, upstreams map[string]string) *ReleaseAnalyzer {
	ra := &ReleaseAnalyzer{
		llm:       llm,
		upstreams: upstreams,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
	if githubBaseURL != "" || githubToken != "" {
		ra.gh = github.NewClient(githubBaseURL, githubToken)
	}
	return ra
}

// Name returns "release".
func (ra *ReleaseAnalyzer) Name() string { return "release" }

// Analyze collects release metadata and sends it to the LLM for analysis. It
// fails closed: if the LLM response cannot be parsed as JSON, an error is
// returned.
func (ra *ReleaseAnalyzer) Analyze(ctx context.Context, req AnalysisRequest) (AnalysisResult, error) {
	metadata, err := ra.collectMetadata(ctx, req.Ecosystem, req.Module, req.Version)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("collecting metadata: %w", err)
	}

	llmReq := provider.Request{
		SystemPrompt: prompt.ReleaseSystemPrompt,
		UserPrompt:   prompt.ReleaseUserPrompt(req.Ecosystem, req.Module, req.Version, metadata),
		MaxTokens:    4096,
	}

	resp, err := ra.llm.Complete(ctx, llmReq)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("LLM completion: %w", err)
	}

	var result AnalysisResult
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		return AnalysisResult{}, fmt.Errorf("parsing LLM response as JSON (fail-closed): %w", err)
	}

	return result, nil
}

// collectMetadata builds a metadata string by fetching registry data (always)
// and GitHub data (best-effort). The data collected depends on the ecosystem.
func (ra *ReleaseAnalyzer) collectMetadata(ctx context.Context, ecosystem, module, version string) (string, error) {
	switch ecosystem {
	case "npm":
		return ra.collectNpmMetadata(ctx, module, version)
	case "pip":
		return ra.collectPipMetadata(ctx, module, version)
	case "rubygems":
		return ra.collectRubyGemsMetadata(ctx, module, version)
	default:
		return ra.collectGoMetadata(ctx, module, version)
	}
}

// collectGoMetadata fetches Go module proxy data and optional GitHub data.
func (ra *ReleaseAnalyzer) collectGoMetadata(ctx context.Context, module, version string) (string, error) {
	base := ra.upstreams["go"]
	if base == "" {
		return "", fmt.Errorf("no upstream configured for go ecosystem")
	}
	base = strings.TrimRight(base, "/")

	var sb strings.Builder
	sb.WriteString("## Registry Data (Go module proxy)\n\n")

	versions, err := ra.fetchGoVersionList(ctx, base, module)
	if err != nil {
		sb.WriteString(fmt.Sprintf("Version list: error (%v)\n\n", err))
	} else {
		sb.WriteString("### Available versions\n")
		for _, v := range versions {
			sb.WriteString(v)
			sb.WriteByte('\n')
		}
		sb.WriteByte('\n')
	}

	versionInfo, err := ra.fetchGoVersionInfo(ctx, base, module, version)
	if err != nil {
		sb.WriteString(fmt.Sprintf("Version info: error (%v)\n\n", err))
	} else {
		sb.WriteString("### Version info\n")
		sb.WriteString(versionInfo)
		sb.WriteString("\n\n")
	}

	currentMod, err := ra.fetchGoMod(ctx, base, module, version)
	if err != nil {
		sb.WriteString(fmt.Sprintf("go.mod: error (%v)\n\n", err))
	} else {
		sb.WriteString("### go.mod (current version)\n```\n")
		sb.WriteString(currentMod)
		sb.WriteString("\n```\n\n")
	}

	prevVersion := ""
	if versions != nil {
		prevVersion = findPreviousVersion(versions, version)
	}
	if prevVersion == "" {
		prevVersion = guessPreviousTag(version)
	}
	if prevVersion != "" {
		prevMod, err := ra.fetchGoMod(ctx, base, module, prevVersion)
		if err == nil {
			sb.WriteString(fmt.Sprintf("### go.mod (previous version %s)\n```\n", prevVersion))
			sb.WriteString(prevMod)
			sb.WriteString("\n```\n\n")
		}
	}

	owner, repo := parseGitHubPath(module)
	ra.appendGitHubData(ctx, &sb, owner, repo, prevVersion, version)

	return sb.String(), nil
}

// collectNpmMetadata fetches npm registry metadata.
func (ra *ReleaseAnalyzer) collectNpmMetadata(ctx context.Context, module, version string) (string, error) {
	base := ra.upstreams["npm"]
	if base == "" {
		return "", fmt.Errorf("no upstream configured for npm ecosystem")
	}
	base = strings.TrimRight(base, "/")

	url := fmt.Sprintf("%s/%s", base, module)
	body, err := ra.httpGet(ctx, url)
	if err != nil {
		return "", fmt.Errorf("fetch npm metadata: %w", err)
	}

	var pkg struct {
		Name        string                       `json:"name"`
		Time        map[string]string            `json:"time"`
		Maintainers []struct{ Name, Email string } `json:"maintainers"`
		Versions    map[string]json.RawMessage   `json:"versions"`
		Repository  struct{ URL string }         `json:"repository"`
	}
	if err := json.Unmarshal([]byte(body), &pkg); err != nil {
		return "", fmt.Errorf("decode npm metadata: %w", err)
	}

	var sb strings.Builder
	sb.WriteString("## Registry Data (npm)\n\n")

	// Version list and publish times
	sb.WriteString("### Available versions and publish times\n")
	for v, t := range pkg.Time {
		if v == "created" || v == "modified" {
			continue
		}
		sb.WriteString(fmt.Sprintf("- %s: %s\n", v, t))
	}
	sb.WriteByte('\n')

	// Maintainers
	sb.WriteString("### Maintainers\n")
	for _, m := range pkg.Maintainers {
		sb.WriteString(fmt.Sprintf("- %s <%s>\n", m.Name, m.Email))
	}
	sb.WriteByte('\n')

	// Current version dependencies
	if raw, ok := pkg.Versions[version]; ok {
		var ver struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(raw, &ver) == nil {
			sb.WriteString("### Dependencies (current version)\n")
			for dep, v := range ver.Dependencies {
				sb.WriteString(fmt.Sprintf("- %s: %s\n", dep, v))
			}
			sb.WriteByte('\n')
		}
	}

	// Previous version dependencies for diff
	versions := make([]string, 0, len(pkg.Versions))
	for v := range pkg.Versions {
		versions = append(versions, v)
	}
	prevVersion := findPreviousVersion(versions, version)
	if prevVersion != "" {
		if raw, ok := pkg.Versions[prevVersion]; ok {
			var ver struct {
				Dependencies map[string]string `json:"dependencies"`
			}
			if json.Unmarshal(raw, &ver) == nil {
				sb.WriteString(fmt.Sprintf("### Dependencies (previous version %s)\n", prevVersion))
				for dep, v := range ver.Dependencies {
					sb.WriteString(fmt.Sprintf("- %s: %s\n", dep, v))
				}
				sb.WriteByte('\n')
			}
		}
	}

	// GitHub data from repository field
	owner, repo := parseNpmGitHubURL(pkg.Repository.URL)
	ra.appendGitHubData(ctx, &sb, owner, repo, prevVersion, version)

	return sb.String(), nil
}

// collectPipMetadata fetches PyPI metadata.
func (ra *ReleaseAnalyzer) collectPipMetadata(ctx context.Context, module, version string) (string, error) {
	base := ra.upstreams["pip"]
	if base == "" {
		return "", fmt.Errorf("no upstream configured for pip ecosystem")
	}
	base = strings.TrimRight(base, "/")

	url := fmt.Sprintf("%s/pypi/%s/json", base, module)
	body, err := ra.httpGet(ctx, url)
	if err != nil {
		return "", fmt.Errorf("fetch PyPI metadata: %w", err)
	}

	var pkg struct {
		Info struct {
			Name        string `json:"name"`
			Author      string `json:"author"`
			AuthorEmail string `json:"author_email"`
			RequiresDist []string `json:"requires_dist"`
			ProjectURLs map[string]string `json:"project_urls"`
		} `json:"info"`
		Releases map[string][]struct {
			UploadTime string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	if err := json.Unmarshal([]byte(body), &pkg); err != nil {
		return "", fmt.Errorf("decode PyPI metadata: %w", err)
	}

	var sb strings.Builder
	sb.WriteString("## Registry Data (PyPI)\n\n")

	// Version list and publish times
	sb.WriteString("### Available versions and publish times\n")
	for v, urls := range pkg.Releases {
		t := ""
		if len(urls) > 0 {
			t = urls[0].UploadTime
		}
		sb.WriteString(fmt.Sprintf("- %s: %s\n", v, t))
	}
	sb.WriteByte('\n')

	// Author
	sb.WriteString(fmt.Sprintf("### Author\n- %s <%s>\n\n", pkg.Info.Author, pkg.Info.AuthorEmail))

	// Dependencies
	if len(pkg.Info.RequiresDist) > 0 {
		sb.WriteString("### Dependencies (requires_dist)\n")
		for _, dep := range pkg.Info.RequiresDist {
			sb.WriteString(fmt.Sprintf("- %s\n", dep))
		}
		sb.WriteByte('\n')
	}

	// Compute previous version for GitHub compare
	pipVersions := make([]string, 0, len(pkg.Releases))
	for v := range pkg.Releases {
		pipVersions = append(pipVersions, v)
	}
	pipPrevVersion := findPreviousVersion(pipVersions, version)

	// GitHub from project URLs
	owner, repo := parsePipGitHubURL(pkg.Info.ProjectURLs)
	ra.appendGitHubData(ctx, &sb, owner, repo, pipPrevVersion, version)

	return sb.String(), nil
}

// collectRubyGemsMetadata fetches RubyGems metadata.
func (ra *ReleaseAnalyzer) collectRubyGemsMetadata(ctx context.Context, module, version string) (string, error) {
	base := ra.upstreams["rubygems"]
	if base == "" {
		return "", fmt.Errorf("no upstream configured for rubygems ecosystem")
	}
	base = strings.TrimRight(base, "/")

	var sb strings.Builder
	sb.WriteString("## Registry Data (RubyGems)\n\n")

	// Fetch version list
	gemPrevVersion := ""
	versionsURL := fmt.Sprintf("%s/api/v1/versions/%s.json", base, module)
	versionsBody, err := ra.httpGet(ctx, versionsURL)
	if err != nil {
		sb.WriteString(fmt.Sprintf("Versions: error (%v)\n\n", err))
	} else {
		var gems []struct {
			Number    string `json:"number"`
			CreatedAt string `json:"created_at"`
			Authors   string `json:"authors"`
		}
		if json.Unmarshal([]byte(versionsBody), &gems) == nil {
			sb.WriteString("### Available versions\n")
			gemVersions := make([]string, 0, len(gems))
			for _, g := range gems {
				sb.WriteString(fmt.Sprintf("- %s: published %s by %s\n", g.Number, g.CreatedAt, g.Authors))
				gemVersions = append(gemVersions, g.Number)
			}
			sb.WriteByte('\n')
			gemPrevVersion = findPreviousVersion(gemVersions, version)
		}
	}

	// Fetch gem info for current version
	gemURL := fmt.Sprintf("%s/api/v2/rubygems/%s/versions/%s.json", base, module, version)
	gemBody, err := ra.httpGet(ctx, gemURL)
	if err != nil {
		sb.WriteString(fmt.Sprintf("Gem info: error (%v)\n\n", err))
	} else {
		var gem struct {
			Authors       string `json:"authors"`
			Description   string `json:"description"`
			SourceCodeURI string `json:"source_code_uri"`
			Dependencies  struct {
				Runtime []struct {
					Name         string `json:"name"`
					Requirements string `json:"requirements"`
				} `json:"runtime"`
			} `json:"dependencies"`
		}
		if json.Unmarshal([]byte(gemBody), &gem) == nil {
			sb.WriteString(fmt.Sprintf("### Gem Info\nAuthors: %s\nDescription: %s\n\n", gem.Authors, gem.Description))
			if len(gem.Dependencies.Runtime) > 0 {
				sb.WriteString("### Runtime Dependencies\n")
				for _, d := range gem.Dependencies.Runtime {
					sb.WriteString(fmt.Sprintf("- %s %s\n", d.Name, d.Requirements))
				}
				sb.WriteByte('\n')
			}

			// GitHub from source_code_uri
			owner, repo := parseGenericGitHubURL(gem.SourceCodeURI)
			ra.appendGitHubData(ctx, &sb, owner, repo, gemPrevVersion, version)
		}
	}

	return sb.String(), nil
}

// parseGitHubPath extracts owner and repo from a module path that starts with
// "github.com/". Returns empty strings for non-GitHub modules.
func parseGitHubPath(module string) (owner, repo string) {
	if !strings.HasPrefix(module, "github.com/") {
		return "", ""
	}
	parts := strings.SplitN(strings.TrimPrefix(module, "github.com/"), "/", 3)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// appendGitHubData appends GitHub repository data to the metadata string
// if a GitHub client is available and owner/repo are non-empty.
func (ra *ReleaseAnalyzer) appendGitHubData(ctx context.Context, sb *strings.Builder, owner, repo, prevVersion, version string) {
	if ra.gh == nil || owner == "" || repo == "" {
		return
	}
	sb.WriteString("## GitHub Data\n\n")

	repoInfo, err := ra.gh.FetchRepoInfo(ctx, owner, repo)
	if err == nil {
		sb.WriteString(fmt.Sprintf("### Repository\nOwner: %s\nStars: %d\nForks: %d\nCreated: %s\n\n",
			repoInfo.Owner, repoInfo.Stars, repoInfo.Forks, repoInfo.CreatedAt.Format(time.RFC3339)))
	}

	contribs, err := ra.gh.FetchContributors(ctx, owner, repo)
	if err == nil && len(contribs) > 0 {
		sb.WriteString("### Contributors\n")
		for _, c := range contribs {
			sb.WriteString(fmt.Sprintf("- %s: %d contributions, account created %s, %d public repos\n",
				c.Login, c.Contributions, c.CreatedAt.Format(time.RFC3339), c.PublicRepos))
		}
		sb.WriteByte('\n')
	}

	if prevVersion != "" {
		cmp, err := ra.gh.FetchCompare(ctx, owner, repo, prevVersion, version)
		if err == nil {
			sb.WriteString(fmt.Sprintf("### Compare %s...%s\nTotal commits: %d\n", prevVersion, version, cmp.TotalCommits))
			for _, f := range cmp.Files {
				sb.WriteString(fmt.Sprintf("- %s: +%d/-%d\n", f.Filename, f.Additions, f.Deletions))
			}
			sb.WriteByte('\n')
		}
	}
}

// parseNpmGitHubURL extracts owner/repo from an npm repository URL like
// "git+https://github.com/owner/repo.git" or "https://github.com/owner/repo".
func parseNpmGitHubURL(repoURL string) (owner, repo string) {
	return parseGenericGitHubURL(repoURL)
}

// parsePipGitHubURL extracts owner/repo from PyPI project_urls.
func parsePipGitHubURL(projectURLs map[string]string) (owner, repo string) {
	for _, url := range projectURLs {
		if owner, repo := parseGenericGitHubURL(url); owner != "" {
			return owner, repo
		}
	}
	return "", ""
}

// parseGenericGitHubURL extracts owner/repo from any GitHub URL.
func parseGenericGitHubURL(rawURL string) (owner, repo string) {
	// Strip common prefixes
	s := rawURL
	s = strings.TrimPrefix(s, "git+")
	s = strings.TrimPrefix(s, "git://")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimRight(s, "/")

	if !strings.HasPrefix(s, "github.com/") {
		return "", ""
	}
	parts := strings.SplitN(strings.TrimPrefix(s, "github.com/"), "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", ""
	}
	return parts[0], parts[1]
}

// --- Go-specific fetch methods ---

// fetchGoVersionList fetches the list of known versions from the Go module proxy.
func (ra *ReleaseAnalyzer) fetchGoVersionList(ctx context.Context, base, module string) ([]string, error) {
	url := fmt.Sprintf("%s/%s/@v/list", base, module)
	body, err := ra.httpGet(ctx, url)
	if err != nil {
		return nil, err
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return nil, nil
	}
	return strings.Split(body, "\n"), nil
}

// fetchGoVersionInfo fetches the .info JSON for a specific version and returns
// the Time field as a string.
func (ra *ReleaseAnalyzer) fetchGoVersionInfo(ctx context.Context, base, module, version string) (string, error) {
	url := fmt.Sprintf("%s/%s/@v/%s.info", base, module, version)
	body, err := ra.httpGet(ctx, url)
	if err != nil {
		return "", err
	}

	var info struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
	}
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		return body, nil // return raw if not parseable
	}
	return fmt.Sprintf("Version: %s, Time: %s", info.Version, info.Time.Format(time.RFC3339)), nil
}

// fetchGoMod fetches the go.mod file for a specific version from the proxy.
func (ra *ReleaseAnalyzer) fetchGoMod(ctx context.Context, base, module, version string) (string, error) {
	url := fmt.Sprintf("%s/%s/@v/%s.mod", base, module, version)
	return ra.httpGet(ctx, url)
}

// httpGet is a small helper that performs a GET and returns the body as a string.
func (ra *ReleaseAnalyzer) httpGet(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := ra.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// findPreviousVersion returns the version immediately before current in the
// list, or empty if not found.
func findPreviousVersion(versions []string, current string) string {
	for i, v := range versions {
		if v == current && i > 0 {
			return versions[i-1]
		}
	}
	return ""
}

// guessPreviousTag attempts a simple heuristic to guess the previous version
// tag: it decrements the last numeric component. For example, v1.0.1 becomes
// v1.0.0. Returns empty if the patch is 0 or the format is unexpected.
func guessPreviousTag(version string) string {
	// Expect format like v1.2.3
	if !strings.HasPrefix(version, "v") {
		return ""
	}

	parts := strings.Split(version[1:], ".")
	if len(parts) != 3 {
		return ""
	}

	patch := parts[2]
	if patch == "" || patch == "0" {
		return ""
	}

	// Decrement last character if it's a digit > 0.
	lastChar := patch[len(patch)-1]
	if lastChar < '1' || lastChar > '9' {
		return ""
	}

	newPatch := patch[:len(patch)-1] + string(lastChar-1)
	return "v" + parts[0] + "." + parts[1] + "." + newPatch
}
