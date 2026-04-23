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

// CodeAnalyzer uses an LLM to analyze the source code of a Go module for
// supply-chain security threats.
type CodeAnalyzer struct {
	llm            provider.Provider
	upstreamURL    string
	maxSourceBytes int
	client         *http.Client
}

// NewCodeAnalyzer creates a CodeAnalyzer that fetches archives from upstreamURL
// and sends at most maxSourceBytes of source to the LLM for review.
func NewCodeAnalyzer(llm provider.Provider, upstreamURL string, maxSourceBytes int) *CodeAnalyzer {
	return &CodeAnalyzer{
		llm:            llm,
		upstreamURL:    strings.TrimRight(upstreamURL, "/"),
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
	zipData, err := ca.fetchArchive(ctx, req.Module, req.Version)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("fetching archive: %w", err)
	}

	files, err := source.ExtractFiles(zipData, ca.maxSourceBytes)
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

// fetchArchive downloads the module zip from the upstream proxy.
func (ca *CodeAnalyzer) fetchArchive(ctx context.Context, module, version string) ([]byte, error) {
	url := fmt.Sprintf("%s/%s/@v/%s.zip", ca.upstreamURL, module, version)

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
