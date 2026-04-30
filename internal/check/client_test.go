package check

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ariary/soa/pkg/checkapi"
)

func TestCheckAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/check" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var req checkapi.CheckRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Module != "github.com/foo/bar" {
			t.Errorf("unexpected module: %s", req.Module)
		}
		json.NewEncoder(w).Encode(checkapi.CheckResponse{
			Status: checkapi.StatusAllowed,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 5*time.Second, 100*time.Millisecond)
	resp, err := c.Check(context.Background(), checkapi.CheckRequest{
		Module: "github.com/foo/bar", Version: "v1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != checkapi.StatusAllowed {
		t.Errorf("expected allowed, got %s", resp.Status)
	}
}

func TestCheckBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{
			Status: checkapi.StatusBlocked,
			Reason: "published 2 days ago",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 5*time.Second, 100*time.Millisecond)
	resp, err := c.Check(context.Background(), checkapi.CheckRequest{
		Module: "github.com/foo/bar", Version: "v1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != checkapi.StatusBlocked {
		t.Errorf("expected blocked, got %s", resp.Status)
	}
	if resp.Reason != "published 2 days ago" {
		t.Errorf("expected reason, got %s", resp.Reason)
	}
}

func TestCheckProcessingThenAllowed(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/check" {
			json.NewEncoder(w).Encode(checkapi.CheckResponse{
				Status:   checkapi.StatusProcessing,
				ID:       "job-42",
				Progress: 0.1,
			})
			return
		}
		calls++
		if calls < 3 {
			json.NewEncoder(w).Encode(checkapi.CheckResponse{
				Status:   checkapi.StatusProcessing,
				ID:       "job-42",
				Progress: float64(calls) * 0.3,
			})
		} else {
			json.NewEncoder(w).Encode(checkapi.CheckResponse{
				Status: checkapi.StatusAllowed,
			})
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 5*time.Second, 50*time.Millisecond)
	resp, err := c.Check(context.Background(), checkapi.CheckRequest{
		Module: "github.com/foo/bar", Version: "v1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != checkapi.StatusAllowed {
		t.Errorf("expected allowed after polling, got %s", resp.Status)
	}
}

func TestCheckUnreachable_FailClosed(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", 1*time.Second, 100*time.Millisecond)
	resp, err := c.Check(context.Background(), checkapi.CheckRequest{
		Module: "github.com/foo/bar", Version: "v1.0.0",
	})
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
	if resp.Status != checkapi.StatusBlocked {
		t.Errorf("expected blocked on error, got %s", resp.Status)
	}
}

func TestCheckWithProgress_CallsCallback(t *testing.T) {
	calls := 0
	pollCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/check" && r.Method == http.MethodPost {
			// Return processing status to trigger progress callback
			json.NewEncoder(w).Encode(checkapi.CheckResponse{
				Status:   checkapi.StatusProcessing,
				ID:       "job-progress",
				Progress: 0.1,
			})
			return
		}
		// Poll endpoint
		pollCount++
		if pollCount < 2 {
			json.NewEncoder(w).Encode(checkapi.CheckResponse{
				Status:   checkapi.StatusProcessing,
				ID:       "job-progress",
				Progress: 0.5,
			})
		} else {
			json.NewEncoder(w).Encode(checkapi.CheckResponse{
				Status: checkapi.StatusAllowed,
			})
		}
	}))
	defer srv.Close()

	var progressValues []float64
	onProgress := func(progress float64) {
		calls++
		progressValues = append(progressValues, progress)
	}

	c := NewClient(srv.URL, 5*time.Second, 50*time.Millisecond)
	resp, err := c.CheckWithProgress(context.Background(), checkapi.CheckRequest{
		Module: "github.com/foo/bar", Version: "v1.0.0",
	}, onProgress)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != checkapi.StatusAllowed {
		t.Errorf("expected allowed, got %s", resp.Status)
	}
	if calls == 0 {
		t.Error("expected onProgress to be called at least once")
	}
	// The initial processing response (0.1) should trigger onProgress
	if len(progressValues) == 0 || progressValues[0] != 0.1 {
		t.Errorf("expected first progress value to be 0.1, got %v", progressValues)
	}
}

func TestCheckWithProgress_NoCallbackOnNonProcessing(t *testing.T) {
	// When the initial response is NOT processing, onProgress should NOT be called.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{
			Status: checkapi.StatusAllowed,
		})
	}))
	defer srv.Close()

	called := false
	onProgress := func(progress float64) {
		called = true
	}

	c := NewClient(srv.URL, 5*time.Second, 50*time.Millisecond)
	resp, err := c.CheckWithProgress(context.Background(), checkapi.CheckRequest{
		Module: "github.com/foo/bar", Version: "v1.0.0",
	}, onProgress)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != checkapi.StatusAllowed {
		t.Errorf("expected allowed, got %s", resp.Status)
	}
	if called {
		t.Error("onProgress should not be called when response is not processing")
	}
}
