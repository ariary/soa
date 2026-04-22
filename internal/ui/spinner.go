package ui

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

var frames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'}

type entry struct {
	module   string
	version  string
	progress float64
	done     bool
	allowed  bool
	reason   string
}

type Spinner struct {
	mu      sync.Mutex
	w       io.Writer
	plain   bool
	entries map[string]*entry
	stop    chan struct{}
	wg      sync.WaitGroup
	frame   int
}

func NewSpinner(w io.Writer, plain bool) *Spinner {
	s := &Spinner{
		w:       w,
		plain:   plain,
		entries: make(map[string]*entry),
		stop:    make(chan struct{}),
	}
	s.wg.Add(1)
	go s.loop()
	return s
}

func (s *Spinner) Start(module, version string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[module] = &entry{module: module, version: version}
	if s.plain {
		fmt.Fprintf(s.w, "[soa] scanning %s@%s...\n", module, version)
	}
}

func (s *Spinner) SetProgress(module string, progress float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[module]; ok {
		e.progress = progress
	}
}

func (s *Spinner) Stop(module string, allowed bool, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[module]; ok {
		e.done = true
		e.allowed = allowed
		e.reason = reason
	}
	if s.plain {
		if allowed {
			fmt.Fprintf(s.w, "[soa] ✓ %s allowed\n", module)
		} else {
			fmt.Fprintf(s.w, "[soa] ✗ %s blocked: %s\n", module, reason)
		}
	}
}

func (s *Spinner) Shutdown() {
	close(s.stop)
	s.wg.Wait()
	s.render(true)
}

func (s *Spinner) loop() {
	defer s.wg.Done()
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			if !s.plain {
				s.render(false)
			}
		}
	}
}

func (s *Spinner) render(final bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.plain {
		return
	}

	for _, e := range s.entries {
		if e.done {
			if e.allowed {
				fmt.Fprintf(s.w, "\033[2K\r[soa] ✓ %s@%s allowed\n", e.module, e.version)
			} else {
				fmt.Fprintf(s.w, "\033[2K\r[soa] ✗ %s@%s blocked: %s\n", e.module, e.version, e.reason)
			}
		} else if !final {
			line := fmt.Sprintf("[soa] %c scanning %s@%s", frames[s.frame%len(frames)], e.module, e.version)
			if e.progress > 0 {
				line += " " + progressBar(e.progress)
			}
			fmt.Fprintf(s.w, "\033[2K\r%s", line)
		}
	}
	s.frame++

	for k, e := range s.entries {
		if e.done {
			delete(s.entries, k)
		}
	}
}

func progressBar(p float64) string {
	width := 10
	filled := min(int(p*float64(width)), width)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return fmt.Sprintf("[%s %d%%]", bar, int(p*100))
}
