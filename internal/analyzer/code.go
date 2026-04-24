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
	"github.com/ariary/soa/internal/provider"
	"github.com/ariary/soa/internal/source"
)

// CodeAnalyzer uses an LLM to analyze the source code of a package for
// supply-chain security threats. Supports Go, npm, pip, and RubyGems ecosystems.
type CodeAnalyzer struct {
	llm            provider.Provider
	upstreams      map[string]string
	maxSourceBytes int
	client         *http.Client
}

// NewCodeAnalyzer creates a CodeAnalyzer that fetches archives from the
// ecosystem-appropriate upstream URL and sends at most maxSourceBytes of source
// to the LLM for review.
func NewCodeAnalyzer(llm provider.Provider, upstreams map[string]string, maxSourceBytes int) *CodeAnalyzer {
	return &CodeAnalyzer{
		llm:            llm,
		upstreams:      upstreams,
		maxSourceBytes: maxSourceBytes,
		client:         &http.Client{Timeout: 60 * time.Second},
	}
}

// Name returns "code".
func (ca *CodeAnalyzer) Name() string { return "code" }

// Analyze fetches the module archive, extracts source files, sends them to the
// LLM for analysis, and returns the parsed result. It fails closed: if the LLM
// response cannot be parsed as JSON, an error is returned.
func (ca *CodeAnalyzer) Analyze(ctx context.Context, req AnalysisRequest) (AnalysisResult, error) {
	archiveData, err := ca.fetchArchive(ctx, req.Ecosystem, req.Module, req.Version)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("fetching archive: %w", err)
	}

	format := archiveFormat(req.Ecosystem)
	files, err := source.Extract(archiveData, format, ca.maxSourceBytes)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("extracting files: %w", err)
	}

	fileList, sourceCode := formatFiles(files)

	llmReq := provider.Request{
		SystemPrompt: prompt.CodeSystemPrompt,
		UserPrompt:   prompt.CodeUserPrompt(req.Module, req.Version, fileList, sourceCode),
		MaxTokens:    4096,
	}

	resp, err := ca.llm.Complete(ctx, llmReq)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("LLM completion: %w", err)
	}

	var result AnalysisResult
	if err := json.Unmarshal([]byte(resp.Content), &result); err != nil {
		return AnalysisResult{}, fmt.Errorf("parsing LLM response as JSON (fail-closed): %w", err)
	}

	return result, nil
}

// archiveFormat returns the archive format string for the given ecosystem.
func archiveFormat(ecosystem string) string {
	switch ecosystem {
	case "npm", "pip":
		return "tgz"
	case "rubygems":
		return "gem"
	default:
		return "zip"
	}
}

// fetchArchive downloads the module archive from the ecosystem-appropriate upstream.
func (ca *CodeAnalyzer) fetchArchive(ctx context.Context, ecosystem, module, version string) ([]byte, error) {
	base, ok := ca.upstreams[ecosystem]
	if !ok {
		return nil, fmt.Errorf("no upstream configured for ecosystem %q", ecosystem)
	}
	base = strings.TrimRight(base, "/")

	var url string
	switch ecosystem {
	case "npm":
		shortName := module
		if idx := strings.LastIndex(module, "/"); idx >= 0 {
			shortName = module[idx+1:]
		}
		url = fmt.Sprintf("%s/%s/-/%s-%s.tgz", base, module, shortName, version)
	case "pip":
		return ca.fetchPipArchive(ctx, base, module, version)
	case "rubygems":
		url = fmt.Sprintf("%s/gems/%s-%s.gem", base, module, version)
	default:
		url = fmt.Sprintf("%s/%s/@v/%s.zip", base, module, version)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := ca.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

// fetchPipArchive fetches package metadata from PyPI and downloads the sdist archive.
func (ca *CodeAnalyzer) fetchPipArchive(ctx context.Context, base, module, version string) ([]byte, error) {
	metaURL := fmt.Sprintf("%s/pypi/%s/%s/json", base, module, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := ca.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var meta struct {
		URLs []struct {
			PackageType string `json:"packagetype"`
			URL         string `json:"url"`
		} `json:"urls"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("decode PyPI metadata: %w", err)
	}

	downloadURL := ""
	for _, u := range meta.URLs {
		if u.PackageType == "sdist" {
			downloadURL = u.URL
			break
		}
	}
	if downloadURL == "" && len(meta.URLs) > 0 {
		downloadURL = meta.URLs[0].URL
	}
	if downloadURL == "" {
		return nil, fmt.Errorf("no download URL found for %s@%s", module, version)
	}

	dlReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, err
	}
	dlResp, err := ca.client.Do(dlReq)
	if err != nil {
		return nil, err
	}
	defer dlResp.Body.Close()
	if dlResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", dlResp.StatusCode, downloadURL)
	}
	return io.ReadAll(dlResp.Body)
}

// formatFiles builds a file listing and concatenated source code block from the
// extracted files.
func formatFiles(files []source.File) (fileList, sourceCode string) {
	var listBuilder, codeBuilder strings.Builder
	for _, f := range files {
		listBuilder.WriteString(f.Path)
		listBuilder.WriteByte('\n')

		codeBuilder.WriteString("### ")
		codeBuilder.WriteString(f.Path)
		codeBuilder.WriteByte('\n')
		codeBuilder.WriteString("```\n")
		codeBuilder.WriteString(f.Content)
		codeBuilder.WriteString("\n```\n\n")
	}
	return listBuilder.String(), codeBuilder.String()
}
