package parser

import (
	"log/slog"
	"testing"

	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
	"github.com/stretchr/testify/assert"
)

// TestParseFailureLine verifies that parseFailureLine correctly extracts
// the fuzzing target name and data ID from various fuzzing log formats.
func TestParseFailureLine(t *testing.T) {
	tests := []struct {
		name           string
		logLine        string
		expectedTarget string
		expectedID     string
	}{
		{
			name: "Seed corpus failure log line",
			logLine: "failure while testing seed corpus " +
				"entry: FuzzFoo/771e938e4458e983",
			expectedTarget: "FuzzFoo",
			expectedID:     "771e938e4458e983",
		},
		{
			name: "Fuzzing failure log with saved input " +
				"path",
			logLine: "Failing input written to testdata/fuzz" +
				"/FuzzFoo/771e938e4458e983",
			expectedTarget: "FuzzFoo",
			expectedID:     "771e938e4458e983",
		},
		{
			name: "Seed corpus failure with seed input",
			logLine: "failure while testing seed corpus " +
				"entry: FuzzFoo/seed#0",
			expectedTarget: "",
			expectedID:     "",
		},
		{
			name: "Non-relevant log line",
			logLine: "elapsed: 0s, gathering baseline " +
				"coverage:",
			expectedTarget: "",
			expectedID:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualTarget, actualID := parseFailureLine(tt.logLine)
			assert.Equal(t, tt.expectedTarget, actualTarget,
				"fuzz target does not match")
			assert.Equal(t, tt.expectedID, actualID,
				"data ID does not match")
		})
	}
}

// TestReadInputData validates the behavior of the readFailingInput method
// in scenarios where the input file is missing or present within the
// provided corpus path.
func TestReadInputData(t *testing.T) {
	tests := []struct {
		name         string
		fuzzTarget   string
		testcaseID   string
		corpusPath   string
		expectedData string
	}{
		{
			name:       "missing input file returns error message",
			fuzzTarget: "FuzzFoo",
			testcaseID: "771e938e4458e888",
			corpusPath: "testdata",
			expectedData: "\n<< failed to read FuzzFoo/7" +
				"71e938e4458e888: open testdata/FuzzFoo/" +
				"771e938e4458e888: no such file or directory" +
				" >>\n",
		},
		{
			name: "existing input file returns correct " +
				"content",
			fuzzTarget: "FuzzFoo",
			testcaseID: "771e938e4458e983",
			corpusPath: "testdata",
			expectedData: "\n\n=== Failing testcase (FuzzFoo/" +
				"771e938e4458e983) ===\ngo test fuzz v1\n" +
				"string(\"0\")\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewFuzzOutputProcessor(&slog.Logger{},
				&config.Config{}, tt.corpusPath, "")

			actualData := processor.readFailingInput(tt.fuzzTarget,
				tt.testcaseID)
			assert.Equal(
				t, tt.expectedData, actualData,
				"Mismatch between expected and actual input "+
					"data",
			)
		})
	}
}
