package analyzer

import "context"

// Finding represents a single security signal detected during analysis.
type Finding struct {
	Signal      string   `json:"signal"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Evidence    []string `json:"evidence"`
	Category    string   `json:"category"`
}

// AnalysisResult holds the complete output of an analysis run.
type AnalysisResult struct {
	Findings []Finding `json:"findings"`
	Block    bool      `json:"block"`
	Summary  string    `json:"summary"`
}

// AnalysisRequest identifies the module and version to analyze.
type AnalysisRequest struct {
	Module  string
	Version string
}

// Analyzer is the interface that all analysis backends must implement.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, req AnalysisRequest) (AnalysisResult, error)
}
