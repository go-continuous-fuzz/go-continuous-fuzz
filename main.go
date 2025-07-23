package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"log/slog"

	flags "github.com/jessevdk/go-flags"
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
	// Initialize a structured logger that outputs logs in text format.
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Load configuration settings from config file or command line flags.
	cfg, err := loadConfig()
	if err != nil {
		var fe *flags.Error
		if errors.As(err, &fe) && fe.Type == flags.ErrHelp {
			// help requested
			return 0
		}

		// Print error if not due to help request.
		logger.Error("Failed to load configuration", "error", err)
		return 1
	}

	// Announce where the fuzzing workload will execute and where its
	// workspace lives.
	if cfg.Fuzz.InCluster {
		logger.Info("Running fuzzing jobs inside Kubernetes",
			"workspacePath", InClusterWorkspacePath)
	} else {
		logger.Info("Running fuzzing jobs in Docker container",
			"workspacePath", filepath.Dir(cfg.Project.SrcDir))

		// Perform workspace cleanup when running in Docker (i.e., not
		// in‑cluster).
		defer cleanupWorkspace(logger, cfg)
	}

	// Create a cancellable context to manage the application's lifecycle.
	appCtx, cancelApp := context.WithCancel(context.Background())
	defer cancelApp()

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
