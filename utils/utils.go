package utils

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
)

// CleanupWorkspace deletes the temp directory to reset the workspace state.
// Any errors encountered during removal are logged, but do not stop execution.
func CleanupWorkspace(logger *slog.Logger, cfg *config.Config) {
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

// CalculateFuzzSeconds calculate per-target fuzz duration:
// (SyncFrequency * NumWorkers) / totalTargets.
func CalculateFuzzSeconds(syncFrequency time.Duration, numWorkers int,
	totalTargets int) float64 {

	return syncFrequency.Seconds() * float64(numWorkers) /
		float64(totalTargets)
}
