package orchestrator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/internal/manager"
	"github.com/ariary/soa/pkg/checkapi"
)

func TestRunSubprocess_PropagatesExitCode(t *testing.T) {
	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
	}))
	defer checkSrv.Close()

	cfg := config.Config{
		CheckURL:     checkSrv.URL,
		Proxy:        config.ProxyConfig{Port: 0},
		PollInterval: 100 * time.Millisecond,
		CheckTimeout: 5 * time.Second,
	}

	managers := []manager.Manager{&manager.GolangManager{}}

	code := Run(cfg, managers, []string{"true"}, os.Environ(), false)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}

	code = Run(cfg, managers, []string{"false"}, os.Environ(), false)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestRunSubprocess_InjectsEnv(t *testing.T) {
	checkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
	}))
	defer checkSrv.Close()

	cfg := config.Config{
		CheckURL:     checkSrv.URL,
		Proxy:        config.ProxyConfig{Port: 0},
		PollInterval: 100 * time.Millisecond,
		CheckTimeout: 5 * time.Second,
	}

	managers := []manager.Manager{&manager.GolangManager{}}

	code := Run(cfg, managers, []string{"sh", "-c", "echo $GOPROXY | grep -q localhost"}, os.Environ(), false)
	if code != 0 {
		t.Errorf("expected GOPROXY to contain localhost, exit code: %d", code)
	}
}
