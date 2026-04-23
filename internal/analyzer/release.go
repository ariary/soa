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
	llm      provider.Provider
	gh       *github.Client
	proxyURL string
	client   *http.Client
}

// NewReleaseAnalyzer creates a ReleaseAnalyzer. A GitHub client is created only
// if githubBaseURL or githubToken is non-empty.
func NewReleaseAnalyzer(llm provider.Provider, githubBaseURL, githubToken, proxyURL string) *ReleaseAnalyzer {
	ra := &ReleaseAnalyzer{
		llm:      llm,
		proxyURL: strings.TrimRight(proxyURL, "/"),
		client:   &http.Client{Timeout: 30 * time.Second},
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
	metadata, err := ra.collectMetadata(ctx, req.Module, req.Version)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("collecting metadata: %w", err)
	}

	llmReq := provider.Request{
		SystemPrompt: prompt.ReleaseSystemPrompt,
		UserPrompt:   prompt.ReleaseUserPrompt(req.Module, req.Version, metadata),
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
// and GitHub data (best-effort, only if GitHub client is available and the
// module is on github.com).
func (ra *ReleaseAnalyzer) collectMetadata(ctx context.Context, module, version string) (string, error) {
	var sb strings.Builder

	// --- Registry data (always) ---
	sb.WriteString("## Registry Data\n\n")

	versions, err := ra.fetchVersionList(ctx, module)
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

	versionInfo, err := ra.fetchVersionInfo(ctx, module, version)
	if err != nil {
		sb.WriteString(fmt.Sprintf("Version info: error (%v)\n\n", err))
	} else {
		sb.WriteString("### Version info\n")
		sb.WriteString(versionInfo)
		sb.WriteString("\n\n")
	}

	// Fetch current go.mod.
	currentMod, err := ra.fetchMod(ctx, module, version)
	if err != nil {
		sb.WriteString(fmt.Sprintf("go.mod: error (%v)\n\n", err))
	} else {
		sb.WriteString("### go.mod (current version)\n```\n")
		sb.WriteString(currentMod)
		sb.WriteString("\n```\n\n")
	}

	// Try to get previous version's go.mod for diffing.
	prevVersion := ""
	if versions != nil {
		prevVersion = findPreviousVersion(versions, version)
	}
	if prevVersion == "" {
		prevVersion = guessPreviousTag(version)
	}
	if prevVersion != "" {
		prevMod, err := ra.fetchMod(ctx, module, prevVersion)
		if err == nil {
			sb.WriteString(fmt.Sprintf("### go.mod (previous version %s)\n```\n", prevVersion))
			sb.WriteString(prevMod)
			sb.WriteString("\n```\n\n")
		}
	}

	// --- GitHub data (best-effort) ---
	owner, repo := parseGitHubPath(module)
	if ra.gh != nil && owner != "" && repo != "" {
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

// fetchVersionList fetches the list of known versions from the Go module proxy.
func (ra *ReleaseAnalyzer) fetchVersionList(ctx context.Context, module string) ([]string, error) {
	url := fmt.Sprintf("%s/%s/@v/list", ra.proxyURL, module)
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

// fetchVersionInfo fetches the .info JSON for a specific version and returns
// the Time field as a string.
func (ra *ReleaseAnalyzer) fetchVersionInfo(ctx context.Context, module, version string) (string, error) {
	url := fmt.Sprintf("%s/%s/@v/%s.info", ra.proxyURL, module, version)
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

// fetchMod fetches the go.mod file for a specific version from the proxy.
func (ra *ReleaseAnalyzer) fetchMod(ctx context.Context, module, version string) (string, error) {
	url := fmt.Sprintf("%s/%s/@v/%s.mod", ra.proxyURL, module, version)
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
