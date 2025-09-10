package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	flags "github.com/jessevdk/go-flags"
)

const (
	// TmpProjectDir is the temporary directory where the project is
	// located.
	TmpProjectDir = "project"

	// TmpReportDir is the temporary directory where the coverage reports
	// are located
	TmpReportDir = "reports"

	// TmpBinaryDir is the temporary directory where the fuzz target
	// binaries are located.
	TmpBinaryDir = "binaries"

	// ConfigFilename is the filename for the go-continuous-fuzz
	// configuration file.
	ConfigFilename = "go-continuous-fuzz.conf"

	// ContainerImage specifies the Docker image to use for running the
	// container.
	ContainerImage = "golang:1.24.6"

	// ContainerWorkDir specifies the working directory for the fuzz
	// execution inside the container.
	ContainerWorkDir = "/go-continuous-fuzz-workdir"

	// ContainerCorpusPath specifies the directory inside the container used
	// for the fuzz corpus.
	ContainerCorpusPath = "/go-continuous-fuzz-corpus"

	// ContainerGracePeriod specifies the grace period to account for
	// container startup overhead and ensures that all targets have
	// sufficient time to complete.
	ContainerGracePeriod = 20 * time.Second
)

var (
	// GoContinuousFuzzDir is the base directory where go-continuous-fuzz
	// looks for its configuration file.
	// On Windows, this resolves to:
	//   C:\Users\<username>\AppData\Local\Go-continuous-fuzz
	// On Linux:
	//   ~/.go-continuous-fuzz
	// On macOS:
	//   ~/Library/Application Support/Go-continuous-fuzz
	GoContinuousFuzzDir = btcutil.AppDataDir("go-continuous-fuzz", false)

	// ConfigFile is the full path of go-continuous-fuzz's configuration
	// file.
	ConfigFile = filepath.Join(GoContinuousFuzzDir, ConfigFilename)
)

// Project holds configuration details for the target project under test.
// It includes the Git repository URL, workspace path, S3 bucket name, and the
// local paths for the project, corpus, and coverage reports.
//
//nolint:lll
type Project struct {
	WorkSpacePath string `long:"workspace-path" description:"Absolute path to the directory where go-continuous-fuzz generated files are stored"`

	SrcRepo string `long:"src-repo" description:"Git repo URL of the project to fuzz" required:"true"`

	S3BucketName string `long:"s3-bucket-name" description:"Name of the S3 bucket where the seed corpus will be stored" required:"true"`

	// SrcDir contains the absolute path to the directory where the project
	// to fuzz is located.
	SrcDir string

	// CorpusDir contains the absolute path to the directory where the seed
	// corpus is located
	CorpusDir string

	// CorpusKey is the S3 object key under which the corpus is stored.
	CorpusKey string

	// ReportDir contains the absolute path to the directory where the
	// coverage reports are located.
	ReportDir string

	// BinaryDir contains the absolute path to the directory where the
	// fuzz target binaries are located.
	BinaryDir string
}

// Fuzz defines all fuzzing-related flags and defaults, including the Git
// repository URLs of the project where issues will be opened, which packages to
// fuzz, timeout settings, concurrency parameters and corpus minimize interval.
//
//nolint:lll
type Fuzz struct {
	CrashRepo string `long:"crash-repo" description:"Git repository URL where issues are created for fuzz crashes" required:"true"`

	PkgsPath []string `long:"pkgs-path" description:"List of package paths to fuzz" required:"true"`

	SyncFrequency time.Duration `long:"sync-frequency" description:"Duration between consecutive fuzzing cycles" default:"24h"`

	NumWorkers int `long:"num-workers" description:"Number of concurrent fuzzing workers" default:"1"`

	CorpusMinimizeInterval time.Duration `long:"corpus-minimize-interval" description:"Interval between consecutive corpus minimizations" default:"7d"`

	Iterations int `long:"iterations" description:"Number of fuzzing cycles to run (0 means to run forever)" default:"0"`
}

// Config encapsulates all top-level configuration parameters required to run
// the fuzzing system. It is populated from, in order of priority:
//  1. Command-line flags.
//  2. CONF file (ConfigFile).
//  3. Default
type Config struct {
	Project Project `group:"Project" namespace:"project"`

	Fuzz Fuzz `group:"Fuzz Options" namespace:"fuzz"`
}

// loadConfig reads configuration values from
// (1) a default CONF file and
// (2) any overriding command-line flags.
// It performs validation on required fields and applies defaults where needed.
// Returns a pointer to a Config struct or an error if validation fails.
func loadConfig() (*Config, error) {
	var cfg Config

	// Determine the config file path
	configFilePath := CleanAndExpandPath(ConfigFile)

	// Parse the CONF file (if it exists). Any values in this file
	// populate fields in cfg. If the file is missing, that's okay.
	parser := flags.NewParser(&cfg, flags.Default)
	err := flags.NewIniParser(parser).ParseFile(configFilePath)
	if err != nil {
		var iniErr *flags.IniError
		var flagsErr *flags.Error
		// If it's a parsing related error, then we'll return
		// immediately, otherwise we can proceed as possibly the config
		// file doesn't exist which is OK.
		if errors.As(err, &iniErr) || errors.As(err, &flagsErr) {
			return nil, err
		}
	}

	// Re-parse command-line flags so they override any values from the
	// file.
	if _, err := parser.Parse(); err != nil {
		return nil, err
	}

	// Validate the number of workers to ensure it is within the allowed
	// range.
	maxProcs := runtime.NumCPU()
	if cfg.Fuzz.NumWorkers <= 0 || cfg.Fuzz.NumWorkers > maxProcs {
		return nil, fmt.Errorf("invalid number of workers: %d, "+
			"allowed range is [1, %d]", cfg.Fuzz.NumWorkers,
			runtime.NumCPU())
	}

	// Ensure iterations are non-negative.
	if cfg.Fuzz.Iterations < 0 {
		return nil, fmt.Errorf("invalid number of iterations: %d, "+
			"must be non-negative", cfg.Fuzz.Iterations)
	}

	// Extract the repository name from the source URL and use it to set the
	// corpus key and corpus directory.
	repo, err := extractRepo(cfg.Project.SrcRepo)
	if err != nil {
		return nil, err
	}
	cfg.Project.CorpusKey = fmt.Sprintf("%s_corpus.zip", repo)

	// Set the absolute path to the workspace directory.
	//
	// If the user specifies --workspace-path, use that path directly.
	// Otherwise, create a temporary directory automatically.
	//
	// Having a fixed workspace path is especially useful for debugging,
	// since the generated files will persist if go-continuous-fuzz crashes.
	var tmpDirPath string
	if cfg.Project.WorkSpacePath == "" {
		tmpDirPath, err = os.MkdirTemp("", "go-continuous-fuzz-")
		if err != nil {
			return nil, err
		}
	} else {
		tmpDirPath = CleanAndExpandPath(cfg.Project.WorkSpacePath)
	}

	cfg.Project.SrcDir = filepath.Join(tmpDirPath, TmpProjectDir)
	cfg.Project.CorpusDir = filepath.Join(tmpDirPath,
		fmt.Sprintf("%s_corpus", repo))
	cfg.Project.ReportDir = filepath.Join(tmpDirPath, TmpReportDir)
	cfg.Project.BinaryDir = filepath.Join(tmpDirPath, TmpBinaryDir)

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
