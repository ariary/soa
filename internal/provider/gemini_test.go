package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGeminiName(t *testing.T) {
	g := NewGemini("", "test-key", "gemini-pro")
	if g.Name() != "gemini" {
		t.Errorf("expected Name() = %q, got %q", "gemini", g.Name())
	}
}

func TestGeminiDefaultBaseURL(t *testing.T) {
	g := NewGemini("", "test-key", "gemini-pro")
	if g.baseURL != "https://generativelanguage.googleapis.com/v1beta" {
		t.Errorf("expected default baseURL %q, got %q", "https://generativelanguage.googleapis.com/v1beta", g.baseURL)
	}
}

func TestGeminiCustomBaseURL(t *testing.T) {
	g := NewGemini("https://custom.api.com", "test-key", "gemini-pro")
	if g.baseURL != "https://custom.api.com" {
		t.Errorf("expected baseURL %q, got %q", "https://custom.api.com", g.baseURL)
	}
}

func TestGeminiComplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		// Verify path contains model and generateContent
		expectedPathPrefix := "/models/gemini-pro:generateContent"
		if !strings.HasPrefix(r.URL.Path, expectedPathPrefix) {
			t.Errorf("expected path prefix %q, got %q", expectedPathPrefix, r.URL.Path)
		}

		// Verify API key in query parameter
		key := r.URL.Query().Get("key")
		if key != "test-api-key" {
			t.Errorf("expected key=%q, got %q", "test-api-key", key)
		}

		// Parse and verify request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		defer r.Body.Close()

		var reqBody map[string]interface{}
		if err := json.Unmarshal(body, &reqBody); err != nil {
			t.Fatalf("failed to parse request body: %v", err)
		}

		// Verify contents (user message)
		contents, ok := reqBody["contents"].([]interface{})
		if !ok {
			t.Fatalf("expected contents to be an array, got %T", reqBody["contents"])
		}
		if len(contents) != 1 {
			t.Fatalf("expected 1 content entry, got %d", len(contents))
		}
		content0, _ := contents[0].(map[string]interface{})
		parts, _ := content0["parts"].([]interface{})
		if len(parts) != 1 {
			t.Fatalf("expected 1 part, got %d", len(parts))
		}
		part0, _ := parts[0].(map[string]interface{})
		if part0["text"] != "Analyze this binary." {
			t.Errorf("expected user text %q, got %v", "Analyze this binary.", part0["text"])
		}

		// Verify systemInstruction
		sysInstr, ok := reqBody["systemInstruction"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected systemInstruction to be present")
		}
		sysParts, _ := sysInstr["parts"].([]interface{})
		if len(sysParts) != 1 {
			t.Fatalf("expected 1 system part, got %d", len(sysParts))
		}
		sysPart0, _ := sysParts[0].(map[string]interface{})
		if sysPart0["text"] != "You are a security analyst." {
			t.Errorf("expected system text %q, got %v", "You are a security analyst.", sysPart0["text"])
		}

		// Verify generationConfig
		genCfg, ok := reqBody["generationConfig"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected generationConfig to be present")
		}
		if genCfg["responseMimeType"] != "application/json" {
			t.Errorf("expected responseMimeType=%q, got %v", "application/json", genCfg["responseMimeType"])
		}
		maxOutputTokens, ok := genCfg["maxOutputTokens"].(float64)
		if !ok || int(maxOutputTokens) != 1024 {
			t.Errorf("expected maxOutputTokens=1024, got %v", genCfg["maxOutputTokens"])
		}

		// Return mock response
		resp := map[string]interface{}{
			"candidates": []map[string]interface{}{
				{
					"content": map[string]interface{}{
						"parts": []map[string]interface{}{
							{"text": `{"verdict":"safe"}`},
						},
					},
				},
			},
			"usageMetadata": map[string]interface{}{
				"promptTokenCount":     42,
				"candidatesTokenCount": 15,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	g := NewGemini(server.URL, "test-api-key", "gemini-pro")
	resp, err := g.Complete(context.Background(), Request{
		SystemPrompt: "You are a security analyst.",
		UserPrompt:   "Analyze this binary.",
		MaxTokens:    1024,
	})
	if err != nil {
		t.Fatalf("Complete() returned error: %v", err)
	}

	if resp.Content != `{"verdict":"safe"}` {
		t.Errorf("expected content %q, got %q", `{"verdict":"safe"}`, resp.Content)
	}
	if resp.Usage.InputTokens != 42 {
		t.Errorf("expected InputTokens=42, got %d", resp.Usage.InputTokens)
	}
	if resp.Usage.OutputTokens != 15 {
		t.Errorf("expected OutputTokens=15, got %d", resp.Usage.OutputTokens)
	}
}

func TestGeminiCompleteNoMaxTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		var reqBody map[string]interface{}
		json.Unmarshal(body, &reqBody)

		// generationConfig should not have maxOutputTokens when MaxTokens is 0
		genCfg, ok := reqBody["generationConfig"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected generationConfig to be present")
		}
		if _, ok := genCfg["maxOutputTokens"]; ok {
			t.Errorf("expected no maxOutputTokens when MaxTokens=0")
		}

		resp := map[string]interface{}{
			"candidates": []map[string]interface{}{
				{
					"content": map[string]interface{}{
						"parts": []map[string]interface{}{
							{"text": "ok"},
						},
					},
				},
			},
			"usageMetadata": map[string]interface{}{
				"promptTokenCount":     10,
				"candidatesTokenCount": 5,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	g := NewGemini(server.URL, "test-key", "gemini-pro")
	_, err := g.Complete(context.Background(), Request{
		SystemPrompt: "sys",
		UserPrompt:   "usr",
		MaxTokens:    0,
	})
	if err != nil {
		t.Fatalf("Complete() returned error: %v", err)
	}
}

func TestGeminiCompleteHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	g := NewGemini(server.URL, "test-key", "gemini-pro")
	_, err := g.Complete(context.Background(), Request{
		SystemPrompt: "sys",
		UserPrompt:   "usr",
	})
	if err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
}

func TestGeminiCompleteNoCandidates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"candidates": []map[string]interface{}{},
			"usageMetadata": map[string]interface{}{
				"promptTokenCount":     10,
				"candidatesTokenCount": 0,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	g := NewGemini(server.URL, "test-key", "gemini-pro")
	_, err := g.Complete(context.Background(), Request{
		SystemPrompt: "sys",
		UserPrompt:   "usr",
	})
	if err == nil {
		t.Fatal("expected error for empty candidates, got nil")
	}
}
