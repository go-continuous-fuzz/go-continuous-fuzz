package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"log/slog"

	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/scheduler"
	flags "github.com/jessevdk/go-flags"
)

// main is the entry point of the application. It sets up signal handling for
// graceful shutdown, loads configuration, and starts the continuous fuzzing
// cycles.
func main() {
	// Initialize a structured logger that outputs logs in text format.
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Load configuration settings from config file or command line flags.
	cfg, err := config.LoadConfig()
	if err != nil {
		var fe *flags.Error
		if errors.As(err, &fe) && fe.Type == flags.ErrHelp {
			// help requested
			os.Exit(0)
		}

		// Print error if not due to help request.
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
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
	scheduler.RunFuzzingCycles(appCtx, logger, cfg)

	logger.Info("Program exited.")
}
