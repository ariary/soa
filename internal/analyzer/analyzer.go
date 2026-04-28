package analyzer

import (
	"context"
	"encoding/json"
)

// Finding represents a single security signal detected during analysis.
type Finding struct {
	Signal      string          `json:"signal"`
	Severity    string          `json:"severity"`
	Description string          `json:"description"`
	Evidence    FlexibleStrings `json:"evidence"`
	Category    string          `json:"category"`
}

// FlexibleStrings accepts both a JSON string and a JSON array of strings,
// normalising the single-string case into a one-element slice. This makes
// LLM responses that return "evidence":"text" instead of ["text"] parseable.
type FlexibleStrings []string

func (f *FlexibleStrings) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*f = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = []string{s}
		return nil
	}
	*f = nil
	return nil
}

// AnalysisResult holds the complete output of an analysis run.
type AnalysisResult struct {
	Findings []Finding `json:"findings"`
	Block    bool      `json:"block"`
	Summary  string    `json:"summary"`
}

// AnalysisRequest identifies the module and version to analyze.
type AnalysisRequest struct {
	Ecosystem string
	Module    string
	Version   string
}

// Analyzer is the interface that all analysis backends must implement.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, req AnalysisRequest) (AnalysisResult, error)
}
