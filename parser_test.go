package main

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseFileAndLine verifies that parseFileAndLine correctly extracts
// the .go file and line where error occurs from various fuzzing log formats.
func TestParseFileAndLine(t *testing.T) {
	tests := []struct {
		name                string
		logLine             string
		expectedFileAndLine string
	}{
		{
			name: "non relevant log line",
			logLine: "--- FAIL: FuzzParseComplex " +
				"(0.00s)",
			expectedFileAndLine: "",
		},
		{
			name: "custom error output format",
			logLine: "      stringutils_test.go:17: " +
				"Reverse produced invalid UTF-8 string",
			expectedFileAndLine: "stringutils_test.go:17",
		},
		{
			name: "stack-trace line format",
			logLine: "go@1.23/1.23.9/libexec/src/" +
				"testing/fuzz.go:322 +0x49c",
			expectedFileAndLine: "go@1.23/1.23.9/libexec/src/" +
				"testing/fuzz.go:322",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualFileAndLine := parseFileAndLine(tt.logLine)
			assert.Equal(
				t, tt.expectedFileAndLine, actualFileAndLine,
				"extracted file and line did not match",
			)
		})
	}
}

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
			name:         "missing file returns error message",
			fuzzTarget:   "FuzzFoo",
			testcaseID:   "771e938e4458e888",
			corpusPath:   "testdata",
			expectedData: "",
		},
		{
			name: "existing input file returns correct " +
				"content",
			fuzzTarget:   "FuzzFoo",
			testcaseID:   "771e938e4458e983",
			corpusPath:   "testdata",
			expectedData: "go test fuzz v1\nstring(\"0\")\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewFuzzOutputProcessor(&slog.Logger{},
				tt.corpusPath)
			actualData, err := processor.readFailingInput(
				tt.fuzzTarget, tt.testcaseID)

			if tt.expectedData != "" {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedData, actualData,
					"Mismatch between expected and actual "+
						"input data")
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestParseIssueBody verifies that parseIssueBody correctly extracts valid
// failing inputs and handles missing sections from issue body.
func TestParseIssueBody(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		expectedInut string
		expectErrMsg string
	}{
		{
			name: "valid section with input",
			body: "## Error logs\n## Failing " +
				"testcase\n~~~sh\ngo test fuzz v1" +
				"\nstring(\"0\")\n\n~~~\n" + waterMark + "\n",
			expectedInut: "go test fuzz v1\nstring(\"0\")\n",
			expectErrMsg: "",
		},
		{
			name: "valid section with seed input",
			body: "## Error logs\n## Failing " +
				"testcase\n~~~sh\n" + seedCorpusErrMsg +
				"\n~~~\n" + waterMark + "\n",
			expectedInut: seedCorpusErrMsg,
			expectErrMsg: "",
		},
		{
			name:         "missing section",
			body:         "No failing testcase section",
			expectedInut: "",
			expectErrMsg: "failing testcase section not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIssueBody(tt.body)
			if tt.expectErrMsg != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectErrMsg)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedInut, got)
		})
	}
}
