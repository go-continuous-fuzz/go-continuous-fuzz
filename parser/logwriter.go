package parser

import (
	"fmt"
	"os"
)

// LogWriter defines the interface for writing fuzz failure logs to any sink.
type LogWriter interface {
	// Initialize creates (or truncates, if it already exists) the log file
	// at the specified path, preparing the sink for subsequent log output.
	Initialize(logPath string) error

	// WriteLine writes a single line of fuzzer output (followed by a
	// newline) to the underlying log sink.
	WriteLine(line string) error

	// WriteErrorData writes the formatted contents of the failing testcase
	// (plus newline) to the log file.
	WriteErrorData(data string) error

	// Close writes the trailing formatted contents of the failing testcase
	// and closes the underlying file.
	Close(errorData string) error
}

// FileLogWriter is a LogWriter that writes failure logs into a file.
type FileLogWriter struct {
	file *os.File
}

// Initialize creates (or truncates, if it already exists) the log file at the
// specified path, preparing the sink for subsequent log output.
func (fl *FileLogWriter) Initialize(logPath string) error {
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("Failed to create log file: %w", err)
	}

	fl.file = logFile
	return nil
}

// WriteLine writes a single line of fuzzer output (followed by a newline) to
// the underlying log sink.
func (fl *FileLogWriter) WriteLine(line string) error {
	_, err := fl.file.WriteString(line + "\n")
	if err != nil {
		return fmt.Errorf("Failed to write log file: %w", err)
	}

	return nil
}

// WriteErrorData writes the formatted contents of the failing testcase (plus
// newline) to the log file.
func (fl *FileLogWriter) WriteErrorData(data string) error {
	_, err := fl.file.WriteString(data + "\n")
	if err != nil {
		return fmt.Errorf("Failed to write log file: %w", err)
	}

	return nil
}

// Close writes the trailing formatted contents of the failing testcase and
// closes the underlying file.
func (fl *FileLogWriter) Close(errorData string) error {
	if err := fl.WriteErrorData(errorData); err != nil {
		return fmt.Errorf("error data write failed: %w", err)
	}

	return fl.file.Close()
}
