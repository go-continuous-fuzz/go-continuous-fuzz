package config

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

	// ConfigFilename is the filename for the go-continuous-fuzz
	// configuration file.
	ConfigFilename = "go-continuous-fuzz.conf"
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

	CorpusPath string `long:"corpus-path" description:"Absolute path to directory where seed corpus is stored" required:"true"`

	// SrcDir contains the absolute path to the directory where the project
	// to fuzz is located.
	SrcDir string
}

// Fuzz defines all fuzzing-related flags and defaults, including where to
// write results, which packages to fuzz, timeout settings, and concurrency
// parameters.
//
//nolint:lll
type Fuzz struct {
	ResultsPath string `long:"results-path" description:"Path to store fuzzing results" required:"true"`

	PkgsPath []string `long:"pkgs-path" description:"List of package paths to fuzz" required:"true"`

	Time time.Duration `long:"time" description:"Duration between consecutive fuzzing cycles" default:"120s"`

	NumProcesses int `long:"num-processes" description:"Number of concurrent fuzzing processes" default:"1"`
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

// LoadConfig reads configuration values from
// (1) a default CONF file and
// (2) any overriding command-line flags.
// It performs validation on required fields and applies defaults where needed.
// Returns a pointer to a Config struct or an error if validation fails.
func LoadConfig() (*Config, error) {
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

	// Validate the number of processes to ensure it is within the allowed
	// range.
	maxProcs := runtime.NumCPU()
	if cfg.Fuzz.NumProcesses <= 0 || cfg.Fuzz.NumProcesses > maxProcs {
		return nil, fmt.Errorf("invalid number of processes: %d, "+
			"allowed range is [1, %d]", cfg.Fuzz.NumProcesses,
			runtime.NumCPU())
	}

	// As soon as we're done parsing configuration options, ensure all paths
	// to directories and files are cleaned and expanded before attempting
	// to use them later on.
	cfg.Fuzz.ResultsPath = CleanAndExpandPath(cfg.Fuzz.ResultsPath)
	cfg.Project.CorpusPath = CleanAndExpandPath(cfg.Project.CorpusPath)

	// Set the absolute path to the temporary project directory.
	tmpDirPath, err := os.MkdirTemp("", "go-continuous-fuzz-")
	if err != nil {
		return nil, err
	}
	cfg.Project.SrcDir = filepath.Join(tmpDirPath, TmpProjectDir)

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
