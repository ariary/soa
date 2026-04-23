package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAIName(t *testing.T) {
	o := NewOpenAI("", "sk-test", "gpt-4o")
	if o.Name() != "openai" {
		t.Errorf("expected Name() = %q, got %q", "openai", o.Name())
	}
}

func TestOpenAIDefaultBaseURL(t *testing.T) {
	o := NewOpenAI("", "sk-test", "gpt-4o")
	if o.baseURL != "https://api.openai.com/v1" {
		t.Errorf("expected default baseURL %q, got %q", "https://api.openai.com/v1", o.baseURL)
	}
}

func TestOpenAICustomBaseURL(t *testing.T) {
	o := NewOpenAI("https://custom.api.com/v1", "sk-test", "gpt-4o")
	if o.baseURL != "https://custom.api.com/v1" {
		t.Errorf("expected baseURL %q, got %q", "https://custom.api.com/v1", o.baseURL)
	}
}

func TestOpenAIComplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method and path
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/chat/completions" {
			t.Errorf("expected /chat/completions, got %s", r.URL.Path)
		}

		// Verify auth header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer sk-test-key" {
			t.Errorf("expected Authorization %q, got %q", "Bearer sk-test-key", authHeader)
		}

		// Verify content type
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type %q, got %q", "application/json", ct)
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

		// Verify model
		if reqBody["model"] != "gpt-4o" {
			t.Errorf("expected model %q, got %v", "gpt-4o", reqBody["model"])
		}

		// Verify response_format
		respFmt, ok := reqBody["response_format"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected response_format to be present")
		}
		if respFmt["type"] != "json_object" {
			t.Errorf("expected response_format.type=%q, got %v", "json_object", respFmt["type"])
		}

		// Verify messages: should have 2 (system + user)
		messages, ok := reqBody["messages"].([]interface{})
		if !ok {
			t.Fatalf("expected messages to be an array, got %T", reqBody["messages"])
		}
		if len(messages) != 2 {
			t.Fatalf("expected 2 messages, got %d", len(messages))
		}

		msg0, _ := messages[0].(map[string]interface{})
		if msg0["role"] != "system" {
			t.Errorf("expected first message role %q, got %v", "system", msg0["role"])
		}
		if msg0["content"] != "You are a security analyst." {
			t.Errorf("expected system content %q, got %v", "You are a security analyst.", msg0["content"])
		}

		msg1, _ := messages[1].(map[string]interface{})
		if msg1["role"] != "user" {
			t.Errorf("expected second message role %q, got %v", "user", msg1["role"])
		}
		if msg1["content"] != "Analyze this binary." {
			t.Errorf("expected user content %q, got %v", "Analyze this binary.", msg1["content"])
		}

		// Verify max_tokens is set
		maxTokens, ok := reqBody["max_tokens"].(float64)
		if !ok || int(maxTokens) != 1024 {
			t.Errorf("expected max_tokens=1024, got %v", reqBody["max_tokens"])
		}

		// Return mock response
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"role":    "assistant",
						"content": `{"verdict":"safe"}`,
					},
				},
			},
			"usage": map[string]interface{}{
				"prompt_tokens":     42,
				"completion_tokens": 15,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	o := NewOpenAI(server.URL, "sk-test-key", "gpt-4o")
	resp, err := o.Complete(context.Background(), Request{
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

func TestOpenAICompleteNoMaxTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		var reqBody map[string]interface{}
		json.Unmarshal(body, &reqBody)

		// max_tokens should not be present when MaxTokens is 0
		if _, ok := reqBody["max_tokens"]; ok {
			t.Errorf("expected no max_tokens when MaxTokens=0")
		}

		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"role":    "assistant",
						"content": "ok",
					},
				},
			},
			"usage": map[string]interface{}{
				"prompt_tokens":     10,
				"completion_tokens": 5,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	o := NewOpenAI(server.URL, "sk-test", "gpt-4o")
	_, err := o.Complete(context.Background(), Request{
		SystemPrompt: "sys",
		UserPrompt:   "usr",
		MaxTokens:    0,
	})
	if err != nil {
		t.Fatalf("Complete() returned error: %v", err)
	}
}

func TestOpenAICompleteHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	o := NewOpenAI(server.URL, "sk-test", "gpt-4o")
	_, err := o.Complete(context.Background(), Request{
		SystemPrompt: "sys",
		UserPrompt:   "usr",
	})
	if err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
}

func TestOpenAICompleteNoChoices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{},
			"usage": map[string]interface{}{
				"prompt_tokens":     10,
				"completion_tokens": 0,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	o := NewOpenAI(server.URL, "sk-test", "gpt-4o")
	_, err := o.Complete(context.Background(), Request{
		SystemPrompt: "sys",
		UserPrompt:   "usr",
	})
	if err == nil {
		t.Fatal("expected error for empty choices, got nil")
	}
}
