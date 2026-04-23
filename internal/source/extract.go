package source

import (
	"archive/zip"
	"bytes"
	"io"
	"path/filepath"
	"sort"
	"strings"
)

// File represents a single source file extracted from an archive.
type File struct {
	Path    string
	Content string
}

// allowedExtensions is the set of file extensions we keep.
var allowedExtensions = map[string]bool{
	".go":   true,
	".js":   true,
	".py":   true,
	".rb":   true,
	".sh":   true,
	".c":    true,
	".json": true,
	".yaml": true,
	".yml":  true,
	".toml": true,
	".mod":  true,
}

// skippedDirs are directory path components that cause a file to be skipped.
var skippedDirs = []string{"vendor/", "testdata/", "node_modules/", ".git/"}

// ExtractFiles reads a zip archive from bytes, filters and prioritizes files,
// and returns up to maxBytes of source content. At least one file is always
// included even if it exceeds the limit.
func ExtractFiles(zipData []byte, maxBytes int) ([]File, error) {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, err
	}

	var files []File
	for _, zf := range r.File {
		if zf.FileInfo().IsDir() {
			continue
		}

		path := zf.Name

		// Skip files in excluded directories.
		if isSkippedDir(path) {
			continue
		}

		// Keep only allowed extensions.
		ext := filepath.Ext(path)
		if !allowedExtensions[ext] {
			continue
		}

		content, err := readZipFile(zf)
		if err != nil {
			continue // skip unreadable files
		}

		files = append(files, File{Path: path, Content: content})
	}

	// Assign tiers and stable-sort.
	sort.SliceStable(files, func(i, j int) bool {
		return tier(files[i]) < tier(files[j])
	})

	// Fill up to maxBytes, always including at least one file.
	var result []File
	totalBytes := 0
	for i, f := range files {
		size := len(f.Content)
		if i > 0 && totalBytes+size > maxBytes {
			break
		}
		result = append(result, f)
		totalBytes += size
	}

	return result, nil
}

// tier returns the priority tier for a file (lower is higher priority).
func tier(f File) int {
	name := filepath.Base(f.Path)
	ext := filepath.Ext(f.Path)

	// Tier 0: entry points
	if name == "main.go" || name == "setup.py" || name == "package.json" || name == "Makefile" || ext == ".sh" {
		return 0
	}
	if strings.Contains(f.Content, "func init()") {
		return 0
	}

	// Tier 1: suspicious imports
	suspiciousPatterns := []string{
		"net/http", "os/exec", "crypto",
		"child_process", "subprocess", "os.system", "plugin.Open",
	}
	for _, p := range suspiciousPatterns {
		if strings.Contains(f.Content, p) {
			return 1
		}
	}

	// Tier 2: everything else
	return 2
}

// isSkippedDir returns true if the file path contains a skipped directory component.
func isSkippedDir(path string) bool {
	for _, dir := range skippedDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}
	return false
}

// readZipFile reads the full content of a zip file entry.
func readZipFile(zf *zip.File) (string, error) {
	rc, err := zf.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
