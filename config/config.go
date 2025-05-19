package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

const (
	// DefaultFuzzTime specifies the default duration for fuzzing if not
	// overridden by environment variables.
	DefaultFuzzTime = "120s"

	// DefaultCorpusDir is the directory where the fuzzing corpus is stored.
	DefaultCorpusDir = "out/corpus"

	// DefaultProjectDir is the directory where the project is located.
	DefaultProjectDir = "out/project"

	// DefaultReportName is the directory name where fuzzing results are
	// stored.
	DefaultReportName = "fuzz_results"
)

// Config holds the configuration parameters for the fuzzing setup.
type Config struct {
	// ProjectSrcPath is the Git repository URL of the project to be fuzzed.
	ProjectSrcPath string

	// GitStorageRepo is the Git repository where the input corpus is
	// stored.
	GitStorageRepo string

	// Path to store fuzzing results, relative to the current working
	// directory
	FuzzResultsPath string

	// FuzzPkgs are the specific Go packages within the repository that will
	// be fuzzed.
	FuzzPkgs []string

	// FuzzTime is the duration (in seconds) for which the fuzzing engine
	// should run.
	FuzzTime string

	// NumProcesses specifies the number of fuzzing processes to run
	// concurrently.
	NumProcesses int
}

// LoadEnv loads environment variables from a .env file in the current
// directory. It should be called before accessing any environment variables in
// the application. If the file is not found or fails to load, the application
// will return the error.
func LoadEnv() error {
	// If '.env' does not exist, load environment variables from the
	// process's environment
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		return nil
	}

	// load environment variables from a .env file
	if err := godotenv.Load(); err != nil {
		return fmt.Errorf("failed to load .env file: %w", err)
	}
	return nil
}

// calculateProcessCount determines the number of processes to use based on the
// FUZZ_NUM_PROCESSES environment variable. If the variable is set to a valid
// number,it will return that value (capped by the number of available CPUs).
// Otherwise, it returns the number of CPUs available.
func calculateProcessCount() int {
	// Check for a user-specified value in FUZZ_NUM_PROCESSES
	if envVal := os.Getenv("FUZZ_NUM_PROCESSES"); envVal != "" {
		num, err := strconv.Atoi(envVal)

		// Only accept valid, positive integers
		if err == nil && num > 0 {
			maxProcs := runtime.NumCPU()

			// If the user asked for more processes than cores, cap
			// it.
			if num > maxProcs {
				return maxProcs
			}

			// Otherwise, use the user’s requested count
			return num
		}

		// If conversion failed or num <= 0, ignore and fall through to
		// default
	}

	return runtime.NumCPU()
}

// LoadConfig loads the fuzzing configuration from environment variables.
// It sets default values where applicable and returns an error if required
// environment variables are missing or invalid.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		ProjectSrcPath: os.Getenv("PROJECT_SRC_PATH"),
		GitStorageRepo: os.Getenv("GIT_STORAGE_REPO"),
		FuzzTime:       DefaultFuzzTime,
	}

	// Validate required variables
	if cfg.ProjectSrcPath == "" {
		return nil, errors.New("PROJECT_SRC_PATH environment variable" +
			" required")
	}
	if cfg.GitStorageRepo == "" {
		return nil, errors.New("GIT_STORAGE_REPO environment variable" +
			" required")
	}

	// Override default FuzzTime if user provided a value
	if fuzzTimeStr := os.Getenv("FUZZ_TIME"); fuzzTimeStr != "" {
		// parse as integer seconds
		seconds, err := strconv.Atoi(fuzzTimeStr)
		if err != nil {
			return nil, fmt.Errorf("FUZZ_TIME environment "+
				"variable must be a number, got %q",
				fuzzTimeStr)
		}

		cfg.FuzzTime = fmt.Sprintf("%ds", seconds)
	}

	// Determine how many concurrent fuzz processes to spawn
	cfg.NumProcesses = calculateProcessCount()

	// FUZZ_PKG is required: a space-separated list of package names
	// (assumed to match their directory names)
	fuzzPkgs := os.Getenv("FUZZ_PKG")
	if fuzzPkgs == "" {
		return nil, errors.New("FUZZ_PKG environment variable required")
	}
	cfg.FuzzPkgs = strings.Fields(fuzzPkgs) // split on whitespace

	// Build the directory where fuzz reports (and logs) will be written
	// FUZZ_RESULTS_PATH may itself come from an env var (can be empty)
	cfg.FuzzResultsPath = filepath.Join(
		os.Getenv("FUZZ_RESULTS_PATH"), DefaultReportName,
	)

	return cfg, nil
}
