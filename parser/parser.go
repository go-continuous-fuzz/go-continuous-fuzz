package parser

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/utils"
)

var (
	// fuzzFailureRegex matches lines indicating a fuzzing failure or a
	// failing input, capturing the fuzz target name and the corresponding
	// input ID.
	//
	// It matches lines like:
	//   "failure while testing seed corpus entry: FuzzFoo/771e938e4458e983"
	//   "Failing input written to testdata/fuzz/FuzzFoo/771e938e4458e983"
	//
	// Captured groups:
	//   - "target": the fuzz target name (e.g., "FuzzFoo")
	//   - "id": the hexadecimal input ID (e.g., "771e938e4458e983")
	fuzzFailureRegex = regexp.MustCompile(
		`(?:failure while testing seed corpus entry:\s*|Failing ` +
			`input written to\s*testdata/fuzz/)` +
			`(?P<target>[^/]+)/(?P<id>[0-9a-f]+)`,
	)
)

// FuzzProcessor reads a stream of fuzzer output lines, detects failures,
// writes logs, and captures the failing input for later logging.
type FuzzProcessor struct {
	// Logger used to record informational and error messages during
	// processing.
	logger *slog.Logger

	// Configuration settings provided by the user
	cfg *config.Config

	// Path to the directory where the input failing corpus (if any) is
	// stored.
	corpusPath string

	// Name of the fuzz target being processed.
	target string

	// Interface responsible for writing logs to the desired output.
	logWriter LogWriter

	// Tracks the state of the processing, including whether a failure was
	// detected.
	State *ProcessState
}

// ProcessState holds mutable state information while processing fuzzer output.
type ProcessState struct {
	// SeenFailure indicates whether a failure marker line has been spotted.
	SeenFailure bool

	// ErrorData contains the formatted contents of the failing testcase.
	ErrorData string

	// InputPrinted indicates whether the failing input has already been
	// captured.
	InputPrinted bool
}

// NewFuzzProcessor constructs a FuzzProcessor for the given logger, config,
// corpus path, and fuzz target name.
func NewFuzzProcessor(logger *slog.Logger, cfg *config.Config,
	corpusPath string, target string) *FuzzProcessor {

	return &FuzzProcessor{
		logger:     logger,
		cfg:        cfg,
		corpusPath: corpusPath,
		target:     target,
		State:      &ProcessState{},
		logWriter:  &FileLogWriter{},
	}
}

// ProcessStream reads each line from the fuzzing output, processes it (logging
// every line and capturing any failure details), and when complete closes the
// log writer, flushing any accumulated error data.
func (fp *FuzzProcessor) ProcessStream(stream io.Reader) {
	scanner := bufio.NewScanner(stream)

	// Iterate over each line in the output stream.
	for scanner.Scan() {
		// Process the current line to detect any errors or failures.
		// If an error occurs during processing, log it using the
		// provided logWriter.
		if err := fp.processLine(scanner.Text()); err != nil {
			fp.logger.Error("Error processing line", "error", err)
		}
	}

	// Ensure we flush and close the log writer with the final error data.
	defer func() { _ = fp.logWriter.Close(fp.State.ErrorData) }()
}

// processLine handles one line of fuzz output: it logs it, checks for failure
// markers, and if in failure mode, writes lines and captures failing input.
func (fp *FuzzProcessor) processLine(line string) error {
	fp.logger.Info("Fuzzer output", "message", line)

	// If a failure has not yet been detected, check if this line indicates
	// a failure.
	if !fp.State.SeenFailure {
		if err := fp.handleFailureDetection(line); err != nil {
			return fmt.Errorf("failure detection failed: %w", err)
		}
	}

	// If a failure has been detected, process the line to extract and
	// record relevant failure information.
	if fp.State.SeenFailure {
		// Handle the line in the context of a detected failure.
		if err := fp.handleFailureLine(line); err != nil {
			return fmt.Errorf("failure line handling failed: %w",
				err)
		}
	}

	return nil
}

// handleFailureDetection looks for the first "--- FAIL:" marker. When found,
// it initializes the failure log file for subsequent lines.
func (fp *FuzzProcessor) handleFailureDetection(line string) error {
	// Check if the line contains the failure marker.
	if strings.Contains(line, "--- FAIL:") {
		// Mark that a failure has been detected.
		fp.State.SeenFailure = true

		// Construct the log file name and path for storing failure
		// details.
		logFileName := fmt.Sprintf("%s_failure.log", fp.target)
		logPath := filepath.Join(fp.cfg.FuzzResultsPath, logFileName)

		// Ensure the FuzzResultsPath directory exists (creates parents
		// as needed)
		if err := utils.EnsureDirExists(
			fp.cfg.FuzzResultsPath); err != nil {
			return fmt.Errorf("failed to create fuzz result file: "+
				"%w", err)
		}

		// Initialize the log writer with the constructed path.
		if err := fp.logWriter.Initialize(logPath); err != nil {
			return fmt.Errorf("log writer initialization failed: "+
				"%w", err)
		}

		fp.logger.Info("Failure log initialized", "path", logPath)
	}
	return nil
}

// handleFailureLine writes the line to the log, then on the first occurrence
// of a failure-input marker extracts the testcase and reads its contents.
func (fp *FuzzProcessor) handleFailureLine(line string) error {
	// Log the current line to the failure log file.
	if err := fp.logWriter.WriteLine(line); err != nil {
		return fmt.Errorf("failed to write log line: %w", err)
	}

	// If the failing input has already been printed, no further action is
	// needed.
	if fp.State.InputPrinted {
		return nil
	}

	// Parse the line to extract the fuzz target and ID (hex) of the failing
	// input.
	// When a fuzz target encounters a failure during f.Add, the crash is
	// printed, but no input is saved to testdata/fuzz.
	//
	// The log output typically appears as:
	//   failure while testing seed corpus entry: FuzzFoo/seed#0
	//
	// As a result, no error data will be printed.
	target, id := parseFailureLine(line)
	// If either target or ID is empty, skip further processing.
	if target == "" || id == "" {
		return nil
	}

	// Read the input data associated with the failing target and ID.
	errorData := fp.readInputData(target, id)

	// Store the read input data and mark that the input has been printed.
	fp.State.ErrorData = errorData
	fp.State.InputPrinted = true
	return nil
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

// readInputData attempts to read the failing input file from the corpus and
// returns either its contents or an error placeholder string.
func (fp *FuzzProcessor) readInputData(target, id string) string {
	// Construct the relative path to the failing input file.
	failingInputPath := filepath.Join(target, id)

	// Build the relativr path to the failing input file within the project.
	inputPath := filepath.Join(fp.corpusPath, failingInputPath)

	// Attempt to read the content of the input file.
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
