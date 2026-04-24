package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ariary/soa/internal/analyzer"
	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/internal/registry"
	"github.com/ariary/soa/pkg/checkapi"
)

type cacheEntry struct {
	Module     string    `json:"module"`
	Version    string    `json:"version"`
	ApprovedAt time.Time `json:"approved_at"`
}

type Server struct {
	rules     config.RulesConfig
	cachePath string
	upstreams map[string]string
	mu        sync.RWMutex
	cache     map[string]cacheEntry
	analyzers []analyzer.Analyzer
	jobs      map[string]*AnalysisJob
	jobsMu    sync.RWMutex
}

func NewServer(rules config.RulesConfig, cachePath string, upstreams map[string]string) *Server {
	s := &Server{
		rules:     rules,
		cachePath: cachePath,
		upstreams: upstreams,
		cache:     make(map[string]cacheEntry),
		jobs:      make(map[string]*AnalysisJob),
	}
	s.loadCache()
	s.startJobCleanup()
	return s
}

// SetAnalyzers configures the analyzers that will be run when analysis is
// enabled. This should be called before ListenAndServe.
func (s *Server) SetAnalyzers(analyzers []analyzer.Analyzer) {
	s.analyzers = analyzers
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/check/", s.handlePollJob)
	mux.HandleFunc("/check", s.handleCheck)
	return mux
}

func (s *Server) ListenAndServe(port int) error {
	addr := fmt.Sprintf(":%d", port)
	log.Printf("[server] listening on %s (max_age: enabled=%v min_days=%d, min_versions: enabled=%v count=%d)", addr, s.rules.MaxAge.Enabled, s.rules.MaxAge.MinDays, s.rules.MinVersions.Enabled, s.rules.MinVersions.Count)
	srv := &http.Server{Addr: addr, Handler: s.Handler()}
	return srv.ListenAndServe()
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req checkapi.CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	ecosystem := req.Ecosystem
	if ecosystem == "" {
		http.Error(w, "missing ecosystem field", http.StatusBadRequest)
		return
	}

	log.Printf("[check] [%s] %s@%s", ecosystem, req.Module, req.Version)

	if s.isCached(req.Module, req.Version) {
		log.Printf("[check] %s@%s → allowed (cached)", req.Module, req.Version)
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
		return
	}

	// Min versions check
	if s.rules.MinVersions.Enabled {
		versions, err := registry.FetchVersionList(s.upstreams, ecosystem, req.Module)
		if err != nil {
			reason := fmt.Sprintf("failed to fetch version list: %v", err)
			log.Printf("[check] %s@%s → blocked (%s)", req.Module, req.Version, reason)
			json.NewEncoder(w).Encode(checkapi.CheckResponse{
				Status: checkapi.StatusBlocked,
				Reason: reason,
			})
			return
		}

		if len(versions) < s.rules.MinVersions.Count {
			reason := fmt.Sprintf("module has %d version(s) (minimum: %d)", len(versions), s.rules.MinVersions.Count)
			log.Printf("[check] %s@%s → blocked (%s)", req.Module, req.Version, reason)
			json.NewEncoder(w).Encode(checkapi.CheckResponse{
				Status: checkapi.StatusBlocked,
				Reason: reason,
			})
			return
		}
	}

	// Max age check
	if s.rules.MaxAge.Enabled {
		publishTime, err := registry.FetchPublishTime(s.upstreams, ecosystem, req.Module, req.Version)
		if err != nil {
			reason := fmt.Sprintf("failed to verify package age: %v", err)
			log.Printf("[check] %s@%s → blocked (%s)", req.Module, req.Version, reason)
			json.NewEncoder(w).Encode(checkapi.CheckResponse{
				Status: checkapi.StatusBlocked,
				Reason: reason,
			})
			return
		}

		age := time.Since(publishTime)
		maxAge := time.Duration(s.rules.MaxAge.MinDays) * 24 * time.Hour

		if age < maxAge {
			days := int(age.Hours() / 24)
			reason := fmt.Sprintf("published %d days ago (minimum: %d days)", days, s.rules.MaxAge.MinDays)
			log.Printf("[check] %s@%s → blocked (%s)", req.Module, req.Version, reason)
			json.NewEncoder(w).Encode(checkapi.CheckResponse{
				Status: checkapi.StatusBlocked,
				Reason: reason,
			})
			return
		}
	}

	// Analysis check
	if s.rules.Analysis.Enabled && len(s.analyzers) > 0 {
		job := s.createJob(ecosystem, req.Module, req.Version)
		go s.runAnalysis(job)
		log.Printf("[check] %s@%s → processing (job %s)", req.Module, req.Version, job.ID)
		json.NewEncoder(w).Encode(checkapi.CheckResponse{
			Status: checkapi.StatusProcessing,
			ID:     job.ID,
		})
		return
	}

	s.addToCache(req.Module, req.Version)
	log.Printf("[check] %s@%s → allowed", req.Module, req.Version)
	json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
}

func (s *Server) handlePollJob(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/check/")
	if id == "" {
		http.Error(w, "missing job id", http.StatusBadRequest)
		return
	}
	job := s.getJob(id)
	if job == nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	job.mu.Lock()
	resp := checkapi.CheckResponse{
		Status: job.Status,
		Reason: job.Summary,
		ID:     job.ID,
	}
	job.mu.Unlock()
	json.NewEncoder(w).Encode(resp)
}

func cacheKey(module, version string) string {
	return module + "@" + version
}

func (s *Server) isCached(module, version string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.cache[cacheKey(module, version)]
	return ok
}

func (s *Server) addToCache(module, version string) {
	s.mu.Lock()
	s.cache[cacheKey(module, version)] = cacheEntry{
		Module:     module,
		Version:    version,
		ApprovedAt: time.Now(),
	}
	s.mu.Unlock()
	s.saveCache()
}

func (s *Server) loadCache() {
	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		return
	}
	var entries []cacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}
	for _, e := range entries {
		s.cache[cacheKey(e.Module, e.Version)] = e
	}
}

func (s *Server) saveCache() {
	s.mu.RLock()
	entries := make([]cacheEntry, 0, len(s.cache))
	for _, e := range s.cache {
		entries = append(entries, e)
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(s.cachePath, data, 0644)
}
