package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestSpinnerStartStop(t *testing.T) {
	var buf bytes.Buffer
	s := NewSpinner(&buf, false)
	s.Start("github.com/foo/bar", "v1.2.3")
	time.Sleep(150 * time.Millisecond)
	s.Stop("github.com/foo/bar", true, "")
	s.Shutdown()

	out := buf.String()
	if !strings.Contains(out, "foo/bar") {
		t.Errorf("expected module name in output, got: %s", out)
	}
	if !strings.Contains(out, "v1.2.3") {
		t.Errorf("expected version in output, got: %s", out)
	}
}

func TestSpinnerBlocked(t *testing.T) {
	var buf bytes.Buffer
	s := NewSpinner(&buf, false)
	s.Start("github.com/foo/bar", "v1.2.3")
	time.Sleep(100 * time.Millisecond)
	s.Stop("github.com/foo/bar", false, "too new")
	s.Shutdown()

	out := buf.String()
	if !strings.Contains(out, "too new") {
		t.Errorf("expected reason in output, got: %s", out)
	}
}

func TestSpinnerProgress(t *testing.T) {
	var buf bytes.Buffer
	s := NewSpinner(&buf, false)
	s.Start("github.com/foo/bar", "v1.2.3")
	s.SetProgress("github.com/foo/bar", 0.5)
	time.Sleep(150 * time.Millisecond)
	s.Stop("github.com/foo/bar", true, "")
	s.Shutdown()
	// Just checking no panic with progress
}

func TestSpinnerPlainMode(t *testing.T) {
	var buf bytes.Buffer
	s := NewSpinner(&buf, true)
	s.Start("github.com/foo/bar", "v1.2.3")
	time.Sleep(100 * time.Millisecond)
	s.Stop("github.com/foo/bar", true, "")
	s.Shutdown()

	out := buf.String()
	if strings.Contains(out, "\033[") {
		t.Errorf("expected no ANSI in plain mode, got: %s", out)
	}
	if !strings.Contains(out, "foo/bar") {
		t.Errorf("expected module name in plain output, got: %s", out)
	}
}
