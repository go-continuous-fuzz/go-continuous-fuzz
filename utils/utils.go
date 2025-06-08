package utils

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"

	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
	"github.com/otiai10/copy"
)

// CleanupWorkspace deletes the "out" directory to reset the workspace state.
// Any errors encountered during removal are logged, but do not stop execution.
func CleanupWorkspace(logger *slog.Logger) {
	if err := os.RemoveAll("out"); err != nil {
		logger.Error("workspace cleanup failed", "error", err)
	}
}

// SaveFuzzCorpus copies the generated corpus data for a given package and
// target to the configured fuzz results directory. If the corpus directory does
// not exist, it logs an informational message and returns. Any errors during
// directory creation or copying are logged and cause the process to exit.
func SaveFuzzCorpus(logger *slog.Logger, cfg *config.Config, pkg,
	target string) {

	corpusPath := filepath.Join(config.DefaultCorpusDir, pkg, "testdata",
		"fuzz", target)
	if _, err := os.Stat(corpusPath); os.IsNotExist(err) {
		logger.Info("No corpus directory to output", "path", corpusPath)
		return
	}

	// Ensure the FuzzResultsPath directory exists (creates parents as
	// needed)
	fuzzResultsPath := filepath.Join(cfg.Fuzz.ResultsPath, pkg, "testdata",
		"fuzz", target)
	if err := EnsureDirExists(fuzzResultsPath); err != nil {
		logger.Error("failed to create fuzz results directory", "error",
			err, "path", fuzzResultsPath)
		os.Exit(1)
	}

	// Copy corpus to the results directory
	if err := copy.Copy(corpusPath, fuzzResultsPath); err != nil {
		logger.Error("failed to copy corpus", "error", err, "from",
			corpusPath, "to", fuzzResultsPath)
		os.Exit(1)
	}

	logger.Info("Successfully updated corpus directory", "path",
		fuzzResultsPath, "pkg", pkg, "target", target)
}

// EnsureDirExists creates the specified directory and all necessary parents if
// they do not exist. Returns an error if the directory cannot be created.
func EnsureDirExists(dirPath string) error {
	// Ensure the directory exists (creates parents as needed)
	err := os.MkdirAll(dirPath, 0755)
	if err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	return nil
}

// SanitizeURL parses the given raw URL string and returns a sanitized version
// in which any user credentials (e.g., a GitHub Personal Access Token) are
// replaced with a placeholder ("*****"). This ensures that sensitive
// information is not exposed in logs or output. If the URL cannot be parsed,
// the original URL is returned.
func SanitizeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		// If URL parsing fails, return the original URL.
		return rawURL
	}

	// Remove user info (username and password) if present.
	if parsed.User != nil {
		parsed.User = url.User("*****")
	}

	return parsed.String()
}
