package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestZipAndUnzip validates that a directory can be compressed to a ZIP archive
// using zipDir and subsequently decompressed using unzip to reproduce the
// original directory structure and file contents.
func TestZipAndUnZipDir(t *testing.T) {
	// Create source directory with sample files.
	sourceDir := filepath.Join(t.TempDir(), "test_corpus")
	assert.NoError(t, os.Mkdir(sourceDir, 0o755))

	fileContents := map[string][]byte{
		"file1.txt": []byte("testing unzip"),
		"file2.txt": []byte("testing zipDir"),
	}
	for name, data := range fileContents {
		path := filepath.Join(sourceDir, name)
		assert.NoError(t, os.WriteFile(path, data, 0o644))
	}

	// Initialize S3Store for zipping.
	zipStore := &S3Store{
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		corpusDir: sourceDir,
	}

	// Stream ZIP archive into a pipe.
	pr, pw := io.Pipe()
	go func() {
		err := zipStore.zipDir(pw)
		pw.CloseWithError(err)
	}()

	// Write the archive to a separate temporary workspace.
	archiveDir := t.TempDir()
	zipPath := filepath.Join(archiveDir, "out.zip")

	zipFile, err := os.Create(zipPath)
	assert.NoError(t, err)

	_, err = io.Copy(zipFile, pr)
	assert.NoError(t, err)
	assert.NoError(t, zipFile.Close())

	// Initialize S3Store for unzipping.
	unzipStore := &S3Store{
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		corpusDir: filepath.Join(archiveDir, "test_corpus"),
		zipPath:   zipPath,
	}

	// Perform unzip operation.
	assert.NoError(t, unzipStore.unzip())

	// Validate directory entries.
	parent := filepath.Dir(unzipStore.corpusDir)
	entries, err := os.ReadDir(parent)
	assert.NoError(t, err)

	// Expect exactly the ZIP file and the extracted directory
	assert.Len(t, entries, 2)
	for _, e := range entries {
		switch e.Name() {
		case "out.zip":
			assert.False(t, e.IsDir(), "out.zip should not be a "+
				"directory")
		case "test_corpus":
			assert.True(t, e.IsDir(), "test_corpus should be a "+
				"directory")
		default:
			assert.Fail(t, "unexpected entry %q in %s", e.Name(),
				parent)
		}
	}

	// Validate contents of the extracted directory.
	files, err := os.ReadDir(unzipStore.corpusDir)
	assert.NoError(t, err)
	assert.Len(t, files, len(fileContents))

	var fileNames []string
	for _, f := range files {
		fileNames = append(fileNames, f.Name())
		assert.False(t, f.IsDir(), "%s should be a file", f.Name())
	}
	sort.Strings(fileNames)
	assert.Equal(t, []string{"file1.txt", "file2.txt"}, fileNames)

	// Verify file content.
	for name, expected := range fileContents {
		path := filepath.Join(unzipStore.corpusDir, name)
		actual, err := os.ReadFile(path)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	}
}
