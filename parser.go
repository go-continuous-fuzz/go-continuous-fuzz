package main

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// fuzzFailureRegex matches lines indicating a fuzzing failure or a
	// failing input, capturing the fuzz target name and the corresponding
	// input ID.
	//
	// It matches lines like:
	//   "Failing input written to testdata/fuzz/FuzzFoo/771e938e4458e983"
	//
	// Captured groups:
	//   - "target": the fuzz target name (e.g., "FuzzFoo")
	//   - "id": the hexadecimal input ID (e.g., "771e938e4458e983")
	fuzzFailureRegex = regexp.MustCompile(
		`Failing input written to testdata/fuzz/` +
			`(?P<target>[^/]+)/(?P<id>[0-9a-f]+)`,
	)

	// fuzzFileLineRegex matches a stack-trace line indicating a fuzzing
	// error, capturing the .go file name and line number.
	//
	// It matches lines like:
	//   "stringutils_test.go:17: Reverse produced invalid UTF-8 string"
	//
	// Captured groups:
	//   - "file": the .go file name (e.g., "stringutils_test.go")
	//   - "line": the line number (e.g., "17")
	fuzzFileLineRegex = regexp.MustCompile(
		`\s*(?P<file>.*\.go):(?P<line>[0-9]+)`,
	)
)

// fuzzCrash represents information about a crash encountered during fuzz
// testing. It captures the error logs, the input that caused the failure, and
// the location in the code where the first error occurred.
type fuzzCrash struct {
	errorLogs          string
	failingInput       string
	failureFileAndLine string
}

// fuzzOutputProcessor handles parsing and logging of fuzzing output streams,
// detecting failures, and capturing/logging failing input data.
type fuzzOutputProcessor struct {
	// Logger for informational and error messages.
	logger *slog.Logger

	// Directory containing the fuzzing corpus.
	corpusDir string
}

// NewFuzzOutputProcessor constructs a fuzzOutputProcessor for the given logger
// and corpus directory.
func NewFuzzOutputProcessor(logger *slog.Logger,
	corpusDir string) *fuzzOutputProcessor {

	return &fuzzOutputProcessor{
		logger:    logger,
		corpusDir: corpusDir,
	}
}

// processFuzzStream reads each line from the fuzzing output stream, logs all
// lines, and captures failure details if a failure is detected.
func (fp *fuzzOutputProcessor) processFuzzStream(stream io.Reader) (*fuzzCrash,
	error) {

	scanner := bufio.NewScanner(stream)

	// Scan until a failure line is found; if not found, return nil.
	if !fp.scanUntilFailure(scanner) {
		return nil, nil
	}

	// Process and log failure lines, capturing error data.
	return fp.processFailureLines(scanner)
}

// scanUntilFailure scans the output until a failure indicator (--- FAIL:) is
// found. Returns true if a failure line is detected, false otherwise.
func (fp *fuzzOutputProcessor) scanUntilFailure(scanner *bufio.Scanner) bool {
	for scanner.Scan() {
		line := scanner.Text()
		fp.logger.Info("Fuzzer output", "message", line)

		// Detect the start of a failure section.
		if strings.Contains(line, "--- FAIL:") {
			return true
		}
	}
	return false
}

// processFailureLines scans the fuzzer output line by line after a failure is
// detected. It collects relevant log lines, extracts the location of the first
// error for deduplication, attempts to read the failing input data (if
// available), and notify the caller about the crash.
func (fp *fuzzOutputProcessor) processFailureLines(scanner *bufio.Scanner,
) (*fuzzCrash, error) {

	var failingLog string
	var failingInputString string
	var failingFileLine string

	for scanner.Scan() {
		line := scanner.Text()
		fp.logger.Info("Fuzzer output", "message", line)

		// Write the current line to the failure log.
		failingLog += line + "\n"

		// failingFileLine stores the .go file and line where the first
		// error occurred, which is used for deduplication.
		if failingFileLine == "" {
			// Parse the current error line to extract the .go file
			// and line, then assign it to failingFileLine.
			errorFileAndLine := parseFileAndLine(line)

			if errorFileAndLine != "" {
				failingFileLine = errorFileAndLine
			}
		}

		// If error data has already been captured, skip further
		// extraction.
		if failingInputString != "" {
			continue
		}

		// Parse the line to extract the fuzz target and ID (hex) of the
		// failing input.
		// When a fuzz target encounters a failure during f.Add, the
		// crash is printed, but no input is saved to testdata/fuzz.
		//
		// The log output typically appears as:
		//   failure while testing seed corpus entry: FuzzFoo/seed#0
		//
		// As a result, no error data will be printed.
		target, id := parseFailureLine(line)
		// If either target or ID is empty, skip further processing.
		if target == "" || id == "" {
			continue
		}

		// Read and store the input data associated with the failing
		// target and ID.
		var err error
		failingInputString, err = fp.readFailingInput(target, id)
		if err != nil {
			return nil,
				fmt.Errorf("processing fuzz stream: %w", err)
		}
	}

	// Send all captured fuzz crash data to notify the caller.
	return &fuzzCrash{
		errorLogs:          failingLog,
		failingInput:       failingInputString,
		failureFileAndLine: failingFileLine,
	}, nil
}

// parseFileAndLine attempts to extract stack-trace line indicating a fuzzing
// error, capturing the .go file name and line number.
func parseFileAndLine(errorLine string) string {
	// Apply the regular expression to the line to find matches
	matches := fuzzFileLineRegex.FindStringSubmatch(errorLine)

	// Return empty strings if no match is found
	if matches == nil {
		return ""
	}

	var file, line string
	// Iterate over the named subexpressions to assign values of file and
	// line.
	for i, name := range fuzzFileLineRegex.SubexpNames() {
		switch name {
		case "file":
			file = matches[i]
		case "line":
			line = matches[i]
		}
	}
	return file + ":" + line
}

// parseFailureLine attempts to extract the fuzz target name and input ID
// from a line of fuzzing output. It uses a predefined regular expression
// to match lines that indicate a failure, capturing the relevant details
// if the line conforms to the expected format.
func parseFailureLine(line string) (string, string) {
	// Apply the regular expression to the line to find matches
	matches := fuzzFailureRegex.FindStringSubmatch(line)

	// Return empty strings if no match is found
	if matches == nil {
		return "", ""
	}

	var target, id string
	// Iterate over the named subexpressions to assign values of fuzz target
	// and id.
	for i, name := range fuzzFailureRegex.SubexpNames() {
		switch name {
		case "target":
			target = matches[i]
		case "id":
			id = matches[i]
		}
	}
	return target, id
}

// parseIssueBody extracts and returns the content of the "## Failing testcase"
// section from the issue body. This section contains the input that caused a
// crash in the given fuzz target.
func parseIssueBody(body string) (string, error) {
	// failingInputRegex matches an issue body and captures the text inside
	// the "## Failing testcase" section.
	failingInputRegex := regexp.MustCompile(
		`(?s)## Failing testcase\n~~~sh\n(.*?)\n~~~`)
	match := failingInputRegex.FindStringSubmatch(body)
	if len(match) < 2 {
		return "", fmt.Errorf("failing testcase section not found")
	}

	return match[1], nil
}

// readFailingInput attempts to read the failing input file from the corpus
// directory.Returns the file contents or error if reading fails.
func (fp *fuzzOutputProcessor) readFailingInput(target, id string) (string,
	error) {

	// Construct the path to the failing input file.
	failingInputPath := filepath.Join(target, id)
	inputPath := filepath.Join(fp.corpusDir, failingInputPath)

	// Attempt to read the file contents.
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", inputPath, err)
	}

	// If reading succeeds, format the content with a header indicating it's
	// a failing test case.
	return string(data), nil
}
