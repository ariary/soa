package source

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// createTestZip creates an in-memory zip from a map of path->content.
func createTestZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for path, content := range files {
		f, err := w.Create(path)
		if err != nil {
			t.Fatalf("failed to create zip entry %s: %v", path, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write zip entry %s: %v", path, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}
	return buf.Bytes()
}

func TestExtractFiles_BasicGo(t *testing.T) {
	zipData := createTestZip(t, map[string]string{
		"mymod@v1.0.0/main.go":      "package main\n\nfunc main() {}\n",
		"mymod@v1.0.0/lib.go":       "package mymod\n\nfunc Lib() {}\n",
		"mymod@v1.0.0/go.mod":       "module mymod\n\ngo 1.21\n",
		"mymod@v1.0.0/README.md":    "# mymod\n",
		"mymod@v1.0.0/icon.png":     "fake png data",
		"mymod@v1.0.0/vendor/x.go":  "package vendor\n",
	})

	files, err := ExtractFiles(zipData, 1<<20) // 1 MiB limit
	if err != nil {
		t.Fatalf("ExtractFiles failed: %v", err)
	}

	paths := make(map[string]bool)
	for _, f := range files {
		paths[f.Path] = true
	}

	// .go and .mod files should be included
	for _, want := range []string{"mymod@v1.0.0/main.go", "mymod@v1.0.0/lib.go", "mymod@v1.0.0/go.mod"} {
		if !paths[want] {
			t.Errorf("expected file %s to be included, got files: %v", want, keys(paths))
		}
	}

	// vendor/ and .png should be excluded
	for _, excluded := range []string{"mymod@v1.0.0/vendor/x.go", "mymod@v1.0.0/icon.png", "mymod@v1.0.0/README.md"} {
		if paths[excluded] {
			t.Errorf("expected file %s to be excluded", excluded)
		}
	}
}

func TestExtractFiles_TruncatesToMaxBytes(t *testing.T) {
	content := strings.Repeat("a", 1000)
	zipData := createTestZip(t, map[string]string{
		"mod@v1/a.go": content,
		"mod@v1/b.go": content,
		"mod@v1/c.go": content,
	})

	files, err := ExtractFiles(zipData, 1500)
	if err != nil {
		t.Fatalf("ExtractFiles failed: %v", err)
	}

	totalBytes := 0
	for _, f := range files {
		totalBytes += len(f.Content)
	}

	if totalBytes > 1500 {
		t.Errorf("total bytes %d exceeds maxBytes 1500", totalBytes)
	}

	// Should have at least 1 file
	if len(files) < 1 {
		t.Error("expected at least one file")
	}
}

func TestExtractFiles_PrioritizesInitFiles(t *testing.T) {
	zipData := createTestZip(t, map[string]string{
		"mod@v1/utils.go": "package mod\n\nfunc Utils() {}\n",
		"mod@v1/init.go":  "package mod\n\nimport \"net/http\"\n\nfunc init() {\n\t_ = net/http.Get\n}\n",
	})

	files, err := ExtractFiles(zipData, 100)
	if err != nil {
		t.Fatalf("ExtractFiles failed: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("expected at least one file")
	}

	// init.go contains "func init()" (tier 0) and "net/http" (tier 1),
	// so it should come first even with a tight maxBytes budget.
	if files[0].Path != "mod@v1/init.go" {
		t.Errorf("expected first file to be init.go, got %s", files[0].Path)
	}
}

func keys(m map[string]bool) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
