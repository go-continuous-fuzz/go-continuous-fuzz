package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"log/slog"

	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/scheduler"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/utils"
)

// main is the entry point of the application. It sets up signal handling for
// graceful shutdown, loads configuration, and starts the continuous fuzzing
// cycles.
func main() {
	// Display help text if "help" argument is provided.
	if len(os.Args) > 1 && os.Args[1] == "help" {
		fmt.Println(utils.HelpText)
		os.Exit(0)
	}

	// Create a cancellable context to manage the application's lifecycle.
	appCtx, cancelApp := context.WithCancel(context.Background())
	defer cancelApp()

	// Initialize a structured logger that outputs logs in text format.
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Set up signal handling for graceful shutdown on SIGINT and SIGTERM.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info("Received interrupt signal; shutting down " +
			"gracefully...")
		cancelApp()
	}()

	// Load environment variables from a .env file.
	if err := config.LoadEnv(); err != nil {
		logger.Error("Failed to load environment variables", "error",
			err)
		os.Exit(1)
	}

	// Load configuration settings from environment variables.
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Parse the fuzzing cycle duration from configuration (e.g., "20s").
	cycleDuration, err := time.ParseDuration(cfg.FuzzTime)
	if err != nil {
		logger.Error("Error parsing cycle duration", "durationString",
			cfg.FuzzTime, "error", err)
		os.Exit(1)
	}

	// Start the continuous fuzzing cycles.
	scheduler.RunFuzzingCycles(appCtx, logger, cfg, cycleDuration)

	logger.Info("Program exited.")
}
