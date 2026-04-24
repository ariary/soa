package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchPublishTime_Go(t *testing.T) {
	expected := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"Version": "v1.0.0",
			"Time":    expected.Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	upstreams := map[string]string{"go": srv.URL}
	got, err := FetchPublishTime(upstreams, "go", "github.com/foo/bar", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(expected) {
		t.Errorf("got %v, want %v", got, expected)
	}
}

func TestFetchPublishTime_Npm(t *testing.T) {
	expected := time.Date(2024, 3, 10, 8, 30, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"time": map[string]string{
				"2.31.0": expected.Format(time.RFC3339),
			},
		})
	}))
	defer srv.Close()

	upstreams := map[string]string{"npm": srv.URL}
	got, err := FetchPublishTime(upstreams, "npm", "requests", "2.31.0")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(expected) {
		t.Errorf("got %v, want %v", got, expected)
	}
}

func TestFetchPublishTime_Pip(t *testing.T) {
	expected := time.Date(2024, 5, 20, 14, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"urls": []map[string]string{
				{"upload_time_iso_8601": expected.Format(time.RFC3339)},
			},
		})
	}))
	defer srv.Close()

	upstreams := map[string]string{"pip": srv.URL}
	got, err := FetchPublishTime(upstreams, "pip", "requests", "2.31.0")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(expected) {
		t.Errorf("got %v, want %v", got, expected)
	}
}

func TestFetchPublishTime_RubyGems(t *testing.T) {
	expected := time.Date(2024, 2, 1, 10, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"created_at": expected.Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	upstreams := map[string]string{"rubygems": srv.URL}
	got, err := FetchPublishTime(upstreams, "rubygems", "rails", "7.1.3")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(expected) {
		t.Errorf("got %v, want %v", got, expected)
	}
}

func TestFetchPublishTime_UnknownEcosystem(t *testing.T) {
	_, err := FetchPublishTime(nil, "unknown", "foo", "1.0")
	if err == nil {
		t.Fatal("expected error for unknown ecosystem")
	}
}

func TestFetchVersionList_Go(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "v1.0.0\nv1.0.1\nv1.1.0\n")
	}))
	defer srv.Close()

	upstreams := map[string]string{"go": srv.URL}
	versions, err := FetchVersionList(upstreams, "go", "github.com/foo/bar")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 3 {
		t.Errorf("expected 3 versions, got %d", len(versions))
	}
}

func TestFetchVersionList_Npm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"versions": map[string]any{
				"1.0.0": map[string]string{},
				"1.1.0": map[string]string{},
			},
		})
	}))
	defer srv.Close()

	upstreams := map[string]string{"npm": srv.URL}
	versions, err := FetchVersionList(upstreams, "npm", "lodash")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(versions))
	}
}
