package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// cleanupProject deletes the project directory to restart the fuzzing cycle.
func cleanupProject(logger *slog.Logger, cfg *Config) {
	if err := os.RemoveAll(cfg.Project.SrcDir); err != nil {
		logger.Error("project cleanup failed", "error", err)
	}
}

// cleanupWorkspace deletes the temp directory to reset the workspace state.
// Any errors encountered during removal are logged, but do not stop execution.
func cleanupWorkspace(logger *slog.Logger, cfg *Config) {
	// Since the config has the path to the project directory and we want to
	// remove its temporary parent directory, we go up one level to its
	// parent directory.
	parentDir := filepath.Dir(cfg.Project.SrcDir)
	if err := os.RemoveAll(parentDir); err != nil {
		logger.Error("workspace cleanup failed", "error", err)
	}
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

// calculateFuzzSeconds returns the per-target fuzz duration such that all fuzz
// targets can be processed within the given syncFrequency. It calculates the
// duration by dividing syncFrequency by the maximum number of tasks assigned to
// any worker.
func calculateFuzzSeconds(syncFrequency time.Duration, numWorkers int,
	totalTargets int) time.Duration {

	tasksPerWorker := (totalTargets + numWorkers - 1) / numWorkers
	perTargetSeconds := int(syncFrequency.Seconds()) / tasksPerWorker
	return time.Duration(perTargetSeconds) * time.Second
}

// ComputeSHA256Short computes a SHA-256 hash of the error data(*.go:<line>),
// then returns the first 16 characters of the hash.
func ComputeSHA256Short(errorData string) string {
	hash := sha256.Sum256([]byte(errorData))
	return hex.EncodeToString(hash[:])[:16]
}

// FileExistsInDir checks whether a file with the specified name exists
// directly within the given directory.
func FileExistsInDir(dirPath, fileName string) (bool, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return false, err
	}

	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() == fileName {
			return true, nil
		}
	}

	return false, nil
}
