package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ariary/soa/internal/analyzer"
	"github.com/ariary/soa/pkg/checkapi"
)

// AnalysisJob tracks an in-flight analysis of a module version.
type AnalysisJob struct {
	ID        string
	Ecosystem string
	Module    string
	Version   string
	Status    string
	Findings  []analyzer.Finding
	Summary   string
	Done      chan struct{}
	mu        sync.Mutex
}

// createJob initialises a new AnalysisJob, stores it in the server's job map,
// and returns it ready for runAnalysis.
func (s *Server) createJob(ecosystem, module, version string) *AnalysisJob {
	job := &AnalysisJob{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Ecosystem: ecosystem,
		Module:    module,
		Version:   version,
		Status:    checkapi.StatusProcessing,
		Done:      make(chan struct{}),
	}
	s.jobsMu.Lock()
	s.jobs[job.ID] = job
	s.jobsMu.Unlock()
	return job
}

// getJob returns the job with the given ID, or nil if not found.
func (s *Server) getJob(id string) *AnalysisJob {
	s.jobsMu.RLock()
	defer s.jobsMu.RUnlock()
	return s.jobs[id]
}

// runAnalysis runs every registered analyzer in parallel. If any analyzer
// returns an error or a blocking result the whole job is marked blocked
// (fail-closed). If all analyzers pass the module is allowed and cached.
func (s *Server) runAnalysis(job *AnalysisJob) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		name string
		res  analyzer.AnalysisResult
		err  error
	}

	ch := make(chan result, len(s.analyzers))
	for _, a := range s.analyzers {
		go func(a analyzer.Analyzer) {
			res, err := a.Analyze(ctx, analyzer.AnalysisRequest{
				Ecosystem: job.Ecosystem,
				Module:    job.Module,
				Version:   job.Version,
			})
			ch <- result{name: a.Name(), res: res, err: err}
		}(a)
	}

	var allFindings []analyzer.Finding
	blocked := false
	var blockReason string

	for range len(s.analyzers) {
		r := <-ch
		if r.err != nil {
			log.Printf("[analysis] %s error for %s@%s: %v", r.name, job.Module, job.Version, r.err)
			blocked = true
			blockReason = fmt.Sprintf("analyzer %s failed: %v", r.name, r.err)
			cancel()
			break
		}
		allFindings = append(allFindings, r.res.Findings...)
		if r.res.Block {
			log.Printf("[analysis] %s blocked %s@%s: %s", r.name, job.Module, job.Version, r.res.Summary)
			blocked = true
			blockReason = r.res.Summary
			cancel()
			break
		}
	}

	job.mu.Lock()
	job.Findings = allFindings
	if blocked {
		job.Status = checkapi.StatusBlocked
		job.Summary = blockReason
	} else {
		job.Status = checkapi.StatusAllowed
		job.Summary = "all analyzers passed"
		s.addToCache(job.Module, job.Version)
		log.Printf("[analysis] %s@%s → allowed", job.Module, job.Version)
	}
	job.mu.Unlock()
	close(job.Done)
}

// startJobCleanup removes completed jobs every minute to avoid unbounded
// memory growth.
func (s *Server) startJobCleanup() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			s.jobsMu.Lock()
			for id, job := range s.jobs {
				select {
				case <-job.Done:
					delete(s.jobs, id)
				default:
				}
			}
			s.jobsMu.Unlock()
		}
	}()
}
