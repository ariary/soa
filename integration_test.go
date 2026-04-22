//go:build integration

package soa_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/internal/orchestrator"
	"github.com/ariary/soa/pkg/checkapi"
)

func TestEndToEnd_GoGetWithCheckServer(t *testing.T) {
	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
	}))
	defer checkSrv.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/github.com/fake/mod/@v/v1.0.0.info" {
			json.NewEncoder(w).Encode(map[string]any{
				"Version": "v1.0.0",
				"Time":    time.Now().AddDate(0, -1, 0).Format(time.RFC3339),
			})
			return
		}
		if r.URL.Path == "/github.com/fake/mod/@v/v1.0.0.mod" {
			fmt.Fprint(w, "module github.com/fake/mod\n\ngo 1.21\n")
			return
		}
		http.NotFound(w, r)
	}))
	defer upstream.Close()

	cfg := config.Config{
		CheckURL:     checkSrv.URL,
		Proxy:        config.ProxyConfig{Port: 0},
		PollInterval: 50 * time.Millisecond,
		CheckTimeout: 5 * time.Second,
	}

	env := os.Environ()
	env = append(env, "GOPROXY="+upstream.URL)

	managers := []manager.Manager{&manager.GolangManager{}}

	code := orchestrator.Run(cfg, managers, []string{"sh", "-c", "echo $GOPROXY"}, env, false)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
}

func TestEndToEnd_BinaryBuilds(t *testing.T) {
	cmd := exec.Command("go", "build", "-o", "/dev/null", "./cmd/soa/")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build soa: %v\n%s", err, out)
	}
}
