package utils

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
	"github.com/otiai10/copy"
)

const HelpText = `Usage: go run main.go [command]

Commands:
  help      Show this help message and exit.

Environment Variables:
  FUZZ_NUM_PROCESSES
          Specifies the number of fuzzing processes to run concurrently.
          Default: Maximum number of CPU cores available on the machine.

  PROJECT_SRC_PATH    (Required)
          The Git repository URL of the project to be fuzzed.
          Formats:
            - Private: https://oauth2:PAT@github.com/OWNER/REPO.git
            - Public:  https://github.com/OWNER/REPO.git

  GIT_STORAGE_REPO    (Required)
          The Git repository where the input corpus is stored.
          Format: https://oauth2:PAT@github.com/OWNER/STORAGEREPO.git

  FUZZ_TIME
          Duration (in seconds) for which the fuzzing engine should run.
          Default: 120 seconds.

  FUZZ_PKG   (Required)
          The specific Go package within the repository to be fuzzed.

  FUZZ_RESULTS_PATH
          Path to store fuzzing results, relative to the current working
	  directory
          Default: Project root directory

Usage Example:
  Set the necessary environment variables, then start fuzzing:
      go run main.go

For more information, please refer to the project documentation.`

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
	fuzzResultsPath := filepath.Join(cfg.FuzzResultsPath, pkg, "testdata",
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
