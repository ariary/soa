package source

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
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
	if name == "main.go" || name == "setup.py" || name == "package.json" ||
		name == "Makefile" || name == "index.js" || name == "__init__.py" ||
		ext == ".sh" {
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

// Extract reads an archive in the given format and returns prioritized source files.
// Supported formats: "zip", "tgz", "gem".
func Extract(data []byte, format string, maxBytes int) ([]File, error) {
	switch format {
	case "zip":
		return ExtractFiles(data, maxBytes)
	case "tgz":
		return extractTarGz(data, maxBytes)
	case "gem":
		return extractGem(data, maxBytes)
	default:
		return nil, fmt.Errorf("unsupported archive format: %s", format)
	}
}

func extractTarGz(data []byte, maxBytes int) ([]File, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	return extractTar(gr, maxBytes)
}

func extractTar(r io.Reader, maxBytes int) ([]File, error) {
	tr := tar.NewReader(r)
	var files []File

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		if isSkippedDir(hdr.Name) {
			continue
		}

		ext := filepath.Ext(hdr.Name)
		if !allowedExtensions[ext] {
			continue
		}

		content, err := io.ReadAll(tr)
		if err != nil {
			continue
		}

		files = append(files, File{Path: hdr.Name, Content: string(content)})
	}

	sort.SliceStable(files, func(i, j int) bool {
		return tier(files[i]) < tier(files[j])
	})

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

func extractGem(data []byte, maxBytes int) ([]File, error) {
	tr := tar.NewReader(bytes.NewReader(data))

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if hdr.Name == "data.tar.gz" {
			gr, err := gzip.NewReader(tr)
			if err != nil {
				return nil, fmt.Errorf("decompress data.tar.gz: %w", err)
			}
			defer gr.Close()
			return extractTar(gr, maxBytes)
		}
	}

	return nil, fmt.Errorf("data.tar.gz not found in gem")
}
