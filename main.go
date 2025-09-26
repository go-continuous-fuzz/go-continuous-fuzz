package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"log/slog"

	flags "github.com/jessevdk/go-flags"
	"gopkg.in/natefinch/lumberjack.v2"
)

// main is the entry point of the application.
// It runs the main logic and exits with the appropriate status code.
func main() {
	// Start the application and exit with the code.
	exitCode := run()
	os.Exit(exitCode)
}

// run sets up signal handling for graceful shutdown, loads configuration, and
// starts the continuous fuzzing cycles.
func run() int {
	// Load configuration settings from config file or command line flags.
	cfg, err := loadConfig()
	if err != nil {
		var fe *flags.Error
		if errors.As(err, &fe) && fe.Type == flags.ErrHelp {
			// help requested
			return 0
		}

		// Print error if not due to help request.
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v", err)
		return 1
	}

	// Initialize a structured logger that writes to both stdout and the
	// rotating log file.
	logFile := &lumberjack.Logger{
		Filename:   filepath.Join(cfg.LogDir, LogFilename),
		MaxSize:    100,
		MaxBackups: 7,
		MaxAge:     28,
		Compress:   true,
	}
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger := slog.New(slog.NewTextHandler(multiWriter, nil))

	defer cleanupWorkspace(logger, cfg)

	// Create a cancellable context to manage the application's lifecycle.
	appCtx, cancelApp := context.WithCancel(context.Background())
	defer cancelApp()

	// If output is piped to another program and then a SIGINT is sent to
	// the process group, we will receive a SIGPIPE when the other program
	// closes the pipe. In that case, we want the below SIGINT handler to
	// clean things up rather than terminating immediately.
	signal.Ignore(syscall.SIGPIPE)

	// Set up signal handling for graceful shutdown on SIGINT and SIGTERM.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("Received interrupt signal; shutting down " +
			"gracefully...")
		cancelApp()
	}()

	// Start the continuous fuzzing cycles.
	if err := runFuzzingCycles(appCtx, logger, cfg); err != nil {
		logger.Error("Failed to run fuzzing cycles", "error", err)
		return 1
	}

	logger.Info("Program exited.")
	return 0
}
