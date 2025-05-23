package config

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	flags "github.com/jessevdk/go-flags"
)

const (
	// DefaultCorpusDir is the directory where the fuzzing corpus is stored.
	DefaultCorpusDir = "out/corpus"

	// DefaultProjectDir is the directory where the project is located.
	DefaultProjectDir = "out/project"
)

// Config encapsulates all configuration parameters required for the fuzzing
// system. It is populated from environment variables and command-line flags.
//
//nolint:lll
type Config struct {
	ProjectSrcPath string `long:"project_src_path" description:"Git repo URL of the project to fuzz" required:"true" env:"PROJECT_SRC_PATH"`

	GitStorageRepo string `long:"git_storage_repo" description:"Git repository where the input corpus is stored" required:"true" env:"GIT_STORAGE_REPO"`

	FuzzResultsPath string `long:"fuzz_results_path" description:"Path to store fuzzing results" env:"FUZZ_RESULTS_PATH" required:"true"`

	FuzzPkgs []string `long:"fuzz_pkg" description:"Comma-separated list of package names to fuzz" required:"true" env:"FUZZ_PKG" env-delim:","`

	FuzzTime time.Duration `long:"fuzz_time" description:"Duration in seconds for fuzzing run" env:"FUZZ_TIME" default:"120s"`

	NumProcesses int `long:"num_processes" description:"Number of concurrent fuzzing processes" env:"FUZZ_NUM_PROCESSES" default:"1"`
}

// LoadConfig parses configuration from environment variables and command-line
// flags. It validates required fields and applies sensible defaults.
// Returns a pointer to a Config struct or an error if validation fails.
func LoadConfig() (*Config, error) {
	var cfg Config

	// Parse configuration, populating the cfg struct.
	if _, err := flags.Parse(&cfg); err != nil {
		return nil, err
	}

	// Validate the number of processes to ensure it is within the allowed
	// range.
	maxProcs := runtime.NumCPU()
	if cfg.NumProcesses <= 0 || cfg.NumProcesses > maxProcs {
		return nil, fmt.Errorf("invalid number of processes: %d, "+
			"allowed range is [1, %d]", cfg.NumProcesses,
			runtime.NumCPU())
	}

	// As soon as we're done parsing configuration options, ensure all paths
	// to directories and files are cleaned and expanded before attempting
	// to use them later on.
	cfg.FuzzResultsPath = CleanAndExpandPath(cfg.FuzzResultsPath)

	return &cfg, nil
}

// CleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func CleanAndExpandPath(path string) string {
	if path == "" {
		return ""
	}

	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		var homeDir string
		u, err := user.Current()
		if err == nil {
			homeDir = u.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}
