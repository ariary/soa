package server

import (
	"bytes"
	"context"
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
	rules       config.RulesConfig
	cachePath   string
	upstreams   map[string]string
	githubToken string
	mu          sync.RWMutex
	cache       map[string]cacheEntry
	analyzers   []analyzer.Analyzer
	jobs        map[string]*AnalysisJob
	jobsMu      sync.RWMutex
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

	// Known malicious package check (osv.dev MAL-* + GHSA MALWARE)
	if advisoryID, err := s.checkKnownMalware(r.Context(), ecosystem, req.Module, req.Version); err != nil {
		log.Printf("[check] %s@%s malware lookup error: %v", req.Module, req.Version, err)
	} else if advisoryID != "" {
		reason := fmt.Sprintf("known malicious package (%s)", advisoryID)
		log.Printf("[check] %s@%s → blocked (%s)", req.Module, req.Version, reason)
		json.NewEncoder(w).Encode(checkapi.CheckResponse{
			Status: checkapi.StatusBlocked,
			Reason: reason,
		})
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

// SetGithubToken configures the GitHub token for GHSA malware lookups.
func (s *Server) SetGithubToken(token string) {
	s.githubToken = token
}

// osvEcosystem maps soa ecosystem names to osv.dev ecosystem names.
func osvEcosystem(eco string) string {
	switch eco {
	case "go":
		return "Go"
	case "npm":
		return "npm"
	case "pip":
		return "PyPI"
	case "rubygems":
		return "RubyGems"
	default:
		return eco
	}
}

// ghsaEcosystemName maps soa ecosystem names to GitHub Advisory Database ecosystem names.
func ghsaEcosystemName(eco string) string {
	switch eco {
	case "go":
		return "GO"
	case "npm":
		return "NPM"
	case "pip":
		return "PIP"
	case "rubygems":
		return "RUBYGEMS"
	default:
		return strings.ToUpper(eco)
	}
}

var malwareClient = &http.Client{Timeout: 10 * time.Second}

// checkKnownMalware checks both osv.dev (MAL-*) and GHSA (MALWARE classification)
// for known malicious packages. Returns the advisory ID if found.
func (s *Server) checkKnownMalware(ctx context.Context, ecosystem, module, version string) (string, error) {
	// Source 1: osv.dev MAL-*
	if id, err := checkOSVMalware(ctx, ecosystem, module, version); err != nil {
		log.Printf("[check] osv.dev lookup error for %s@%s: %v", module, version, err)
	} else if id != "" {
		return id, nil
	}

	// Source 2: GHSA MALWARE (optional, needs token)
	if s.githubToken != "" {
		if id, err := checkGHSAMalware(ctx, s.githubToken, ecosystem, module, version); err != nil {
			log.Printf("[check] GHSA lookup error for %s@%s: %v", module, version, err)
		} else if id != "" {
			return id, nil
		}
	}

	return "", nil
}

// checkOSVMalware queries osv.dev for known malware advisories (MAL-*).
func checkOSVMalware(ctx context.Context, ecosystem, module, version string) (string, error) {
	payload, _ := json.Marshal(map[string]any{
		"package": map[string]string{
			"ecosystem": osvEcosystem(ecosystem),
			"name":      module,
		},
		"version": version,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := malwareClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("osv.dev returned %d", resp.StatusCode)
	}

	var result struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	for _, v := range result.Vulns {
		if strings.HasPrefix(v.ID, "MAL-") {
			return v.ID, nil
		}
	}
	return "", nil
}

// checkGHSAMalware queries GitHub Advisory Database for MALWARE-classified advisories
// affecting the given package+version.
func checkGHSAMalware(ctx context.Context, token, ecosystem, module, version string) (string, error) {
	query := `query($eco: SecurityAdvisoryEcosystem!, $pkg: String!, $cursor: String) {
  securityVulnerabilities(ecosystem: $eco, package: $pkg, classifications: [MALWARE], first: 25, after: $cursor) {
    nodes {
      advisory { ghsaId }
      vulnerableVersionRange
    }
    pageInfo { hasNextPage endCursor }
  }
}`
	vars := map[string]any{
		"eco": ghsaEcosystemName(ecosystem),
		"pkg": module,
	}

	for {
		body, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.github.com/graphql", bytes.NewReader(body))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := malwareClient.Do(req)
		if err != nil {
			return "", err
		}

		var result struct {
			Data struct {
				SecurityVulnerabilities struct {
					Nodes []struct {
						Advisory struct {
							GhsaID string `json:"ghsaId"`
						} `json:"advisory"`
						VulnerableVersionRange string `json:"vulnerableVersionRange"`
					} `json:"nodes"`
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
				} `json:"securityVulnerabilities"`
			} `json:"data"`
		}
		err = json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if err != nil {
			return "", err
		}

		for _, node := range result.Data.SecurityVulnerabilities.Nodes {
			if matchVersionRange(version, node.VulnerableVersionRange) {
				return node.Advisory.GhsaID, nil
			}
		}

		if !result.Data.SecurityVulnerabilities.PageInfo.HasNextPage {
			break
		}
		vars["cursor"] = result.Data.SecurityVulnerabilities.PageInfo.EndCursor
	}

	return "", nil
}

// matchVersionRange checks if version matches a GHSA vulnerableVersionRange.
// Formats: "= 2.0.7" (exact), ">= 0" (all versions), ">= 1.0, < 2.0" (range).
func matchVersionRange(version, rangeStr string) bool {
	rangeStr = strings.TrimSpace(rangeStr)

	// Handle comma-separated constraints: ">= 1.0.0, < 2.0.0"
	parts := strings.Split(rangeStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if !matchSingleConstraint(version, part) {
			return false
		}
	}
	return true
}

func matchSingleConstraint(version, constraint string) bool {
	constraint = strings.TrimSpace(constraint)

	if strings.HasPrefix(constraint, "= ") {
		return version == strings.TrimSpace(constraint[2:])
	}
	if strings.HasPrefix(constraint, ">= ") {
		return compareVersions(version, strings.TrimSpace(constraint[3:])) >= 0
	}
	if strings.HasPrefix(constraint, "> ") {
		return compareVersions(version, strings.TrimSpace(constraint[2:])) > 0
	}
	if strings.HasPrefix(constraint, "<= ") {
		return compareVersions(version, strings.TrimSpace(constraint[3:])) <= 0
	}
	if strings.HasPrefix(constraint, "< ") {
		return compareVersions(version, strings.TrimSpace(constraint[2:])) < 0
	}
	return false
}

// compareVersions does a basic numeric version comparison.
// Returns -1, 0, or 1 like strings.Compare but for dotted version numbers.
func compareVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := range maxLen {
		var av, bv int
		if i < len(aParts) {
			fmt.Sscanf(aParts[i], "%d", &av)
		}
		if i < len(bParts) {
			fmt.Sscanf(bParts[i], "%d", &bv)
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
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
