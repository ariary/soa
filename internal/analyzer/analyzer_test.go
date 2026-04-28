package analyzer

import (
	"encoding/json"
	"testing"
)

func TestFlexibleStrings_Array(t *testing.T) {
	input := `{"evidence":["line1","line2"]}`
	var f struct {
		Evidence FlexibleStrings `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(input), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(f.Evidence) != 2 || f.Evidence[0] != "line1" || f.Evidence[1] != "line2" {
		t.Errorf("got %v, want [line1 line2]", f.Evidence)
	}
}

func TestFlexibleStrings_String(t *testing.T) {
	input := `{"evidence":"single value"}`
	var f struct {
		Evidence FlexibleStrings `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(input), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(f.Evidence) != 1 || f.Evidence[0] != "single value" {
		t.Errorf("got %v, want [single value]", f.Evidence)
	}
}

func TestFlexibleStrings_Null(t *testing.T) {
	input := `{"evidence":null}`
	var f struct {
		Evidence FlexibleStrings `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(input), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.Evidence != nil {
		t.Errorf("got %v, want nil", f.Evidence)
	}
}

func TestFlexibleStrings_Number(t *testing.T) {
	input := `{"evidence":42}`
	var f struct {
		Evidence FlexibleStrings `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(input), &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.Evidence != nil {
		t.Errorf("got %v, want nil", f.Evidence)
	}
}

func TestFlexibleStrings_InFinding(t *testing.T) {
	// Simulate a typical LLM response where evidence is a string instead of array.
	input := `{
		"block": true,
		"summary": "Malicious",
		"findings": [{
			"signal": "c2",
			"severity": "critical",
			"description": "phones home",
			"evidence": "init() calls http.Post to attacker.com",
			"category": "c2-exfil"
		}]
	}`
	var result AnalysisResult
	if err := json.Unmarshal([]byte(input), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if len(result.Findings[0].Evidence) != 1 {
		t.Errorf("expected 1 evidence entry, got %d", len(result.Findings[0].Evidence))
	}
}
