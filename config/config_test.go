package config

import (
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCalculateProcessCount verifies that the calculateProcessCount function
// correctly interprets the FUZZ_NUM_PROCESSES environment variable under
// various scenarios. It ensures that:
// - Values exceeding the number of CPU cores are capped at the CPU core count.
// - Valid numeric values within the CPU core count are accepted as-is.
// - Negative or non-numeric values default to the CPU core count.
func TestCalculateProcessCount(t *testing.T) {
	tests := []struct {
		name           string
		envValue       string
		expectedResult int
	}{
		{
			name:           "process exceeds CPU cores",
			envValue:       strconv.Itoa(runtime.NumCPU() + 1),
			expectedResult: runtime.NumCPU(),
		},
		{
			name:           "process within CPU cores",
			envValue:       "1",
			expectedResult: 1,
		},
		{
			name:           "negative process value",
			envValue:       "-1",
			expectedResult: runtime.NumCPU(),
		},
		{
			name:           "non-numeric process value",
			envValue:       "five",
			expectedResult: runtime.NumCPU(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set the FUZZ_NUM_PROCESSES environment variable for
			// the test case.
			t.Setenv("FUZZ_NUM_PROCESSES", tt.envValue)

			// Call the function under test.
			actualResult := calculateProcessCount()

			assert.Equal(t, tt.expectedResult, actualResult,
				"calculated process count does not match")
		})
	}
}

// TestLoadConfig validates the LoadConfig function by testing various
// combinations of environment variable inputs. It ensures the function returns
// an appropriate config struct when valid inputs are provided and returns
// descriptive errors when required environment variables are missing or
// malformed.
func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name           string
		projectSrcPath string
		gitStorageRepo string
		fuzzPkgs       string
		fuzzTime       string
		numProcesses   string
		expectErr      bool
		errorMsg       string
		expectedCfg    *Config
	}{
		{
			name:           "missing PROJECT_SRC_PATH",
			projectSrcPath: "",
			expectErr:      true,
			errorMsg: "PROJECT_SRC_PATH environment variable " +
				"required",
		},
		{
			name:           "missing GIT_STORAGE_REPO",
			projectSrcPath: "https://github.com/OWNER/REPO.git",
			expectErr:      true,
			errorMsg: "GIT_STORAGE_REPO environment variable " +
				"required",
		},
		{
			name:           "non-numeric FUZZ_TIME",
			projectSrcPath: "https://github.com/OWNER/REPO.git",
			gitStorageRepo: "https://github.com/OWNER/REPO.git",
			fuzzTime:       "five",
			expectErr:      true,
			errorMsg: "FUZZ_TIME environment variable must be " +
				"a number",
		},
		{
			name:           "missing FUZZ_PKG",
			projectSrcPath: "https://github.com/OWNER/REPO.git",
			gitStorageRepo: "https://github.com/OWNER/REPO.git",
			expectErr:      true,
			errorMsg: "FUZZ_PKG environment variable " +
				"required",
		},
		{
			name:           "valid configuration",
			projectSrcPath: "https://github.com/OWNER/REPO.git",
			gitStorageRepo: "https://github.com/OWNER/REPO.git",
			fuzzTime:       "20",
			fuzzPkgs:       "fuzz parser",
			expectErr:      false,
			expectedCfg: &Config{
				ProjectSrcPath: "https://github.com/OWNER/" +
					"REPO.git",
				GitStorageRepo: "https://github.com/OWNER/" +
					"REPO.git",
				FuzzTime:        "20s",
				NumProcesses:    runtime.NumCPU(),
				FuzzPkgs:        []string{"fuzz", "parser"},
				FuzzResultsPath: "fuzz_results",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables for the test case
			t.Setenv("PROJECT_SRC_PATH", tt.projectSrcPath)
			t.Setenv("GIT_STORAGE_REPO", tt.gitStorageRepo)
			t.Setenv("FUZZ_TIME", tt.fuzzTime)
			t.Setenv("FUZZ_PKG", tt.fuzzPkgs)
			t.Setenv("FUZZ_NUM_PROCESSES", tt.numProcesses)

			actualCfg, err := LoadConfig()

			if tt.expectErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedCfg, actualCfg,
					"Config mismatch")
			}
		})
	}
}
