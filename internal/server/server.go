package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ariary/soa/internal/analyzer"
	"github.com/ariary/soa/internal/config"
	"github.com/ariary/soa/pkg/checkapi"
)

type cacheEntry struct {
	Module     string    `json:"module"`
	Version    string    `json:"version"`
	ApprovedAt time.Time `json:"approved_at"`
}

type Server struct {
	rules       config.RulesConfig
	cachePath   string
	upstreamURL string
	mu          sync.RWMutex
	cache       map[string]cacheEntry
	analyzers   []analyzer.Analyzer
	jobs        map[string]*AnalysisJob
	jobsMu      sync.RWMutex
}

func NewServer(rules config.RulesConfig, cachePath, upstreamURL string) *Server {
	s := &Server{
		rules:       rules,
		cachePath:   cachePath,
		upstreamURL: upstreamURL,
		cache:       make(map[string]cacheEntry),
		jobs:        make(map[string]*AnalysisJob),
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
	log.Printf("[server] listening on %s (max_age: enabled=%v min_days=%d)", addr, s.rules.MaxAge.Enabled, s.rules.MaxAge.MinDays)
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

	log.Printf("[check] %s@%s", req.Module, req.Version)

	if s.isCached(req.Module, req.Version) {
		log.Printf("[check] %s@%s → allowed (cached)", req.Module, req.Version)
		json.NewEncoder(w).Encode(checkapi.CheckResponse{Status: checkapi.StatusAllowed})
		return
	}

	// Max age check
	if s.rules.MaxAge.Enabled {
		publishTime, err := s.fetchPublishTime(req.Module, req.Version)
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
		job := s.createJob(req.Module, req.Version)
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

func (s *Server) fetchPublishTime(module, version string) (time.Time, error) {
	url := fmt.Sprintf("%s/%s/@v/%s.info", s.upstreamURL, module, version)
	resp, err := http.Get(url)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return time.Time{}, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, string(body))
	}

	var info struct {
		Version string    `json:"Version"`
		Time    time.Time `json:"Time"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return time.Time{}, fmt.Errorf("decode .info: %w", err)
	}
	return info.Time, nil
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
