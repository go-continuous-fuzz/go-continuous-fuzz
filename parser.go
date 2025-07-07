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

// fuzzOutputProcessor handles parsing and logging of fuzzing output streams,
// detecting failures, and capturing/logging failing input data.
type fuzzOutputProcessor struct {
	// Logger for informational and error messages.
	logger *slog.Logger

	// Configuration settings provided by the user
	cfg *Config

	// Directory containing the fuzzing corpus.
	corpusDir string

	// Name of the package under test.
	packageName string

	// Name of the fuzz target under test.
	targetName string
}

// NewFuzzOutputProcessor constructs a fuzzOutputProcessor for the given logger,
// config, corpus directory, and fuzz target name.
func NewFuzzOutputProcessor(logger *slog.Logger, cfg *Config, corpusDir, pkg,
	targetName string) *fuzzOutputProcessor {

	return &fuzzOutputProcessor{
		logger:      logger,
		cfg:         cfg,
		corpusDir:   corpusDir,
		packageName: pkg,
		targetName:  targetName,
	}
}

// processFuzzStream reads each line from the fuzzing output stream, logs all
// lines, and captures failure details if a failure is detected. Returns true if
// a failure was found and processed, false otherwise.
func (fp *fuzzOutputProcessor) processFuzzStream(stream io.Reader) bool {
	scanner := bufio.NewScanner(stream)

	// Scan until a failure line is found; if not found, return false.
	if !fp.scanUntilFailure(scanner) {
		return false
	}

	// Process and log failure lines, capturing error data.
	fp.processFailureLines(scanner)

	return true
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

// processFailureLines processes lines after a failure is detected, writes them
// to a log file, and attempts to extract and log the failing input data.
func (fp *fuzzOutputProcessor) processFailureLines(scanner *bufio.Scanner) {
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
		failingInputString = fp.readFailingInput(target, id)
	}

	// If a crash occurs but we cannot obtain the failing input, it likely
	// stems from a seed corpus entry added via f.Add. In that case, report
	// that the failure happened while testing the seed corpus.
	if failingInputString == "" {
		failingInputString = fmt.Sprintf(
			"\n\n=== Failing Testcase ===\n" +
				"Failure occurred while testing the seed " +
				"corpus; please check the entries added via " +
				"f.Add.",
		)
	}

	// Ensure the results directory exists.
	if err := EnsureDirExists(fp.cfg.Fuzz.ResultsPath); err != nil {
		fp.logger.Error("Failed to create fuzz results directory",
			"error", err)
		return
	}

	// Check if the crash has already been recorded to avoid duplicate
	// logging.
	isKnown, logFileName, err := fp.isCrashDuplicate(failingFileLine)
	if err != nil {
		fp.logger.Error("Failed to perform crash deduplication",
			"error", err)
		return
	}
	if isKnown {
		fp.logger.Info("Known crash detected. Please fix the failing "+
			"testcase.", "log_file", logFileName)
		return
	}

	// A new unique crash has been detected. Proceed to log the crash
	// details.
	if err := fp.writeCrashLog(logFileName, failingLog,
		failingInputString); err != nil {
		fp.logger.Error("Failed to write crash log", "error", err)
		return
	}
}

// isCrashDuplicate checks whether a crash with the same hash has already been
// logged. Returns true if the crash is already known, false otherwise, along
// with the generated log file name.
func (fp *fuzzOutputProcessor) isCrashDuplicate(errorData string) (bool,
	string, error) {

	// Compute a short signature hash for the crash to help with
	// deduplication.
	crashHash := ComputeSHA256Short(errorData)

	// Construct the log file name using the package, target name and crash
	// hash.
	logFileName := fmt.Sprintf("%s_%s_%s_failure.log", fp.packageName,
		fp.targetName, crashHash)

	// Check if a log file with the same signature already exists in the
	// fuzz results directory.
	isKnown, err := FileExistsInDir(fp.cfg.Fuzz.ResultsPath, logFileName)
	if err != nil {
		return false, "", fmt.Errorf("checking for existing crash "+
			"log: %w", err)
	}

	return isKnown, logFileName, nil
}

// writeCrashLog writes crash logs into a file at the cfg.Fuzz.ResultsPath
// location.
func (fp *fuzzOutputProcessor) writeCrashLog(logFileName, failingLog,
	failingInputString string) error {

	// Construct the log file path for storing failure details.
	logPath := filepath.Join(fp.cfg.Fuzz.ResultsPath, logFileName)

	// Create the log file for writing.
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("Failed to create log file: %w", err)
	}

	// Ensure the log file is closed at the end.
	defer func() {
		if err := logFile.Close(); err != nil {
			fp.logger.Error("Failed to close log file", "error",
				err)
		}
	}()

	fp.logger.Info("Opened failure log for writing", "path", logPath)

	// Write the error logs to the failure log file.
	_, err = logFile.WriteString(failingLog)
	if err != nil {
		return fmt.Errorf("failed to write log line: %w", err)
	}

	// Write the error data to the log file.
	_, err = logFile.WriteString(failingInputString + "\n")
	if err != nil {
		return fmt.Errorf("failed to write error data: %w", err)
	}

	return nil
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

// readFailingInput attempts to read the failing input file from the corpus
// directory.Returns the file contents or a placeholder string if reading fails.
func (fp *fuzzOutputProcessor) readFailingInput(target, id string) string {
	// Construct the path to the failing input file.
	failingInputPath := filepath.Join(target, id)
	inputPath := filepath.Join(fp.corpusDir, failingInputPath)

	// Attempt to read the file contents.
	data, err := os.ReadFile(inputPath)
	if err != nil {
		// If reading fails, return a placeholder string indicating the
		// failure.
		return fmt.Sprintf("\n<< failed to read %s: %v >>\n",
			failingInputPath, err)
	}

	// If reading succeeds, format the content with a header indicating it's
	// a failing test case.
	return fmt.Sprintf("\n\n=== Failing testcase (%s) ===\n%s",
		failingInputPath, data)
}
