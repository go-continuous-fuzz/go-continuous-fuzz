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
	// InClusterWorkspacePath is the temporary in‑cluster path where the
	// fuzzing workspace is located.
	InClusterWorkspacePath = "/var/lib/go-continuous-fuzz"

	// TmpProjectDir is the temporary directory where the project is
	// located.
	TmpProjectDir = "project"

	// TmpReportDir is the temporary directory where the coverage reports
	// are located
	TmpReportDir = "reports"

	// ConfigFilename is the filename for the go-continuous-fuzz
	// configuration file.
	ConfigFilename = "go-continuous-fuzz.conf"

	// ContainerImage specifies the Docker image to use for running the
	// container.
	ContainerImage = "golang:1.23.9"

	// ContainerProjectPath specifies the root directory for the project
	// inside the container.
	ContainerProjectPath = "/go-continuous-fuzz-project"

	// ContainerCorpusPath specifies the directory inside the container used
	// for the fuzz corpus.
	ContainerCorpusPath = "/go-continuous-fuzz-corpus"

	// FuzzGracePeriod specifies the grace period to account for
	// container/pod startup overhead and ensures that all targets have
	// sufficient time to complete.
	FuzzGracePeriod = 20 * time.Second
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

// Project holds the Git repository URLs for the target project under test,
// as well as the paths to the project and corpus directories.
//
//nolint:lll
type Project struct {
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
}

// Fuzz defines all fuzzing-related flags and defaults, including the Git
// repository URLs of the project where issues will be opened, which packages to
// fuzz, timeout settings, concurrency parameters, whether to run in‑cluster
// or in Docker and k8s namespace.
//
//nolint:lll
type Fuzz struct {
	CrashRepo string `long:"crash-repo" description:"Git repository URL where issues are created for fuzz crashes" required:"true"`

	PkgsPath []string `long:"pkgs-path" description:"List of package paths to fuzz" required:"true"`

	SyncFrequency time.Duration `long:"sync-frequency" description:"Duration between consecutive fuzzing cycles" default:"24h"`

	NumWorkers int `long:"num-workers" description:"Number of concurrent fuzzing workers" default:"1"`

	InCluster bool `long:"in-cluster" description:"Whether to run inside a Kubernetes cluster. Defaults to Docker if unset."`

	NameSpace string `long:"namespace" description:"Kubernetes namespace to use (used when --in-cluster is set)" default:"default"`
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

	// Extract the repository name from the source URL and use it to set the
	// corpus key and corpus directory.
	repo, err := extractRepo(cfg.Project.SrcRepo)
	if err != nil {
		return nil, err
	}
	cfg.Project.CorpusKey = fmt.Sprintf("%s_corpus.zip", repo)

	// Set the absolute path to the temporary project directory.
	var tmpDirPath string
	if cfg.Fuzz.InCluster {
		tmpDirPath = InClusterWorkspacePath
	} else {
		tmpDirPath, err = os.MkdirTemp("", "go-continuous-fuzz-")
		if err != nil {
			return nil, err
		}
	}
	cfg.Project.SrcDir = filepath.Join(tmpDirPath, TmpProjectDir)
	cfg.Project.CorpusDir = filepath.Join(tmpDirPath,
		fmt.Sprintf("%s_corpus", repo))
	cfg.Project.ReportDir = filepath.Join(tmpDirPath, TmpReportDir)

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
