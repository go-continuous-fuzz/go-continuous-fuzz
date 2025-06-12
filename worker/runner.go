package worker

import (
	"context"
	"log/slog"
	"os"

	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/fuzz"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/utils"
	"github.com/go-git/go-git/v5"
)

// Main handles the cloning of repository and the execution of fuzz testing.
// It ensures that any errors encountered during these processes are logged and
// that the workspace is cleaned up appropriately before the program exits.
func Main(ctx context.Context, logger *slog.Logger, cfg *config.Config,
	doneChan chan struct{}) {

	// Close the channel to indicate that the fuzzing cycle has completed,
	// so that the scheduler can perform cleanup.
	defer close(doneChan)

	// Clone the project repository based on the provided configuration.
	logger.Info("Cloning project repository", "url", utils.SanitizeURL(
		cfg.Project.SrcRepo), "path", cfg.Project.SrcDir)

	_, err := git.PlainCloneContext(
		ctx, cfg.Project.SrcDir, false, &git.CloneOptions{
			URL: cfg.Project.SrcRepo,
		},
	)
	if err != nil {
		logger.Error("Project repository cloning failed", "error", err)

		// Perform workspace cleanup before exiting due to the cloning
		// error.
		utils.CleanupWorkspace(logger, cfg)
		os.Exit(1)
	}

	// Execute fuzz testing on the specified packages.
	if err := fuzz.RunFuzzing(ctx, logger, cfg); err != nil {
		logger.Error("Fuzzing process failed", "error", err)

		// Perform workspace cleanup before exiting due to the fuzzing
		// error.
		utils.CleanupWorkspace(logger, cfg)
		os.Exit(1)
	}
}
