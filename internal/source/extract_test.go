package source

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
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

func createTestTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for path, content := range files {
		hdr := &tar.Header{
			Name: path,
			Mode: 0600,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write tar header %s: %v", path, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write tar entry %s: %v", path, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("failed to close tar writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}
	return buf.Bytes()
}

func TestExtract_TarGz(t *testing.T) {
	data := createTestTarGz(t, map[string]string{
		"package/index.js":    "module.exports = {};\n",
		"package/lib/main.js": "const http = require('http');\n",
		"package/README.md":   "# my-package\n",
	})

	files, err := Extract(data, "tgz", 1<<20)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	paths := make(map[string]bool)
	for _, f := range files {
		paths[f.Path] = true
	}

	if !paths["package/index.js"] {
		t.Error("expected index.js to be included")
	}
	if !paths["package/lib/main.js"] {
		t.Error("expected lib/main.js to be included")
	}
	if paths["package/README.md"] {
		t.Error("expected README.md to be excluded")
	}
}

func TestExtract_Zip(t *testing.T) {
	data := createTestZip(t, map[string]string{
		"mod@v1/main.go": "package main\n\nfunc main() {}\n",
	})

	files, err := Extract(data, "zip", 1<<20)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(files) != 1 || files[0].Path != "mod@v1/main.go" {
		t.Errorf("unexpected files: %v", files)
	}
}

func TestExtract_TarGz_Tiering(t *testing.T) {
	data := createTestTarGz(t, map[string]string{
		"package/lib/utils.js": "function utils() {}\n",
		"package/index.js":     "const cp = require('child_process');\n",
	})

	files, err := Extract(data, "tgz", 100)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("expected at least one file")
	}
	if files[0].Path != "package/index.js" {
		t.Errorf("expected first file to be index.js, got %s", files[0].Path)
	}
}

func TestExtractFiles_AtLeastOneFileExceedsMax(t *testing.T) {
	// A single file that exceeds maxBytes should still be included (first file
	// is always included regardless of size).
	bigContent := strings.Repeat("x", 5000)
	zipData := createTestZip(t, map[string]string{
		"mod@v1/main.go": bigContent,
	})

	files, err := ExtractFiles(zipData, 100) // maxBytes = 100, but file is 5000
	if err != nil {
		t.Fatalf("ExtractFiles failed: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected exactly 1 file (first always included), got %d", len(files))
	}
	if len(files[0].Content) != 5000 {
		t.Errorf("expected first file content length 5000, got %d", len(files[0].Content))
	}
}

func TestExtractFiles_ExactMaxBytes(t *testing.T) {
	// Two files whose total size exactly equals maxBytes: both should be included.
	content500 := strings.Repeat("a", 500)
	zipData := createTestZip(t, map[string]string{
		"mod@v1/a.go": content500,
		"mod@v1/b.go": content500,
	})

	files, err := ExtractFiles(zipData, 1000)
	if err != nil {
		t.Fatalf("ExtractFiles failed: %v", err)
	}

	totalBytes := 0
	for _, f := range files {
		totalBytes += len(f.Content)
	}

	if len(files) != 2 {
		t.Errorf("expected 2 files when total == maxBytes, got %d", len(files))
	}
	if totalBytes != 1000 {
		t.Errorf("expected total bytes 1000, got %d", totalBytes)
	}
}

func TestExtractFiles_SecondFileExceedsMax(t *testing.T) {
	// First file fits, second file would push total over maxBytes -> excluded.
	// This tests the boundary condition: i > 0 && totalBytes+size > maxBytes
	zipData := createTestZip(t, map[string]string{
		"mod@v1/main.go": strings.Repeat("a", 600), // tier 0 (entry point)
		"mod@v1/lib.go":  strings.Repeat("b", 500), // tier 2 (normal file)
	})

	files, err := ExtractFiles(zipData, 700) // 600 fits, 600+500=1100 > 700
	if err != nil {
		t.Fatalf("ExtractFiles failed: %v", err)
	}

	if len(files) != 1 {
		t.Errorf("expected 1 file (second excluded by maxBytes), got %d", len(files))
	}
}

func TestExtract_TarGz_AtLeastOneFileExceedsMax(t *testing.T) {
	// Same test for tgz path: single large file should still be included.
	bigContent := strings.Repeat("y", 5000)
	data := createTestTarGz(t, map[string]string{
		"package/index.js": bigContent,
	})

	files, err := Extract(data, "tgz", 100)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected exactly 1 file (first always included), got %d", len(files))
	}
	if len(files[0].Content) != 5000 {
		t.Errorf("expected first file content length 5000, got %d", len(files[0].Content))
	}
}

func TestExtract_TarGz_ExactMaxBytes(t *testing.T) {
	content500 := strings.Repeat("c", 500)
	data := createTestTarGz(t, map[string]string{
		"package/a.js": content500,
		"package/b.js": content500,
	})

	files, err := Extract(data, "tgz", 1000)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	totalBytes := 0
	for _, f := range files {
		totalBytes += len(f.Content)
	}

	if len(files) != 2 {
		t.Errorf("expected 2 files when total == maxBytes, got %d", len(files))
	}
	if totalBytes != 1000 {
		t.Errorf("expected total bytes 1000, got %d", totalBytes)
	}
}
