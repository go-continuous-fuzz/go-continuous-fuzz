package scheduler

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/fuzz"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/utils"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/worker"
	"github.com/go-git/go-git/v5"
	"golang.org/x/sync/errgroup"
)

// StartFuzzCycles runs an infinite loop of fuzzing cycles. Each cycle consists
// of:
//  1. Cloning the Git repository specified in cfg.Project.SrcRepo.
//  2. Launching scheduler goroutines to execute all fuzz targets for a portion
//     of cfg.Fuzz.SyncFrequency.
//  3. Cleaning up the workspace.
//
// The loop repeats until the parent context is canceled. Errors in cloning or
// target discovery are returned immediately.
func StartFuzzCycles(ctx context.Context, logger *slog.Logger, cfg *config.
	Config) {

	for {
		// 1. Clone the repository based on the provided configuration.
		logger.Info("Cloning project repository", "url",
			utils.SanitizeURL(cfg.Project.SrcRepo), "path",
			cfg.Project.SrcDir)

		_, err := git.PlainCloneContext(
			ctx, cfg.Project.SrcDir, false, &git.CloneOptions{
				URL: cfg.Project.SrcRepo,
			},
		)
		if err != nil {
			logger.Error("Failed to clone project repository; "+
				"aborting scheduler", "error", err)

			// Perform workspace cleanup before exiting due to the
			// cloning error.
			utils.CleanupWorkspace(logger, cfg)
			os.Exit(1)
		}

		// 2. Create a scheduler context for this fuzz iteration.
		schedulerCtx, cancelCycle := context.WithCancel(ctx)

		// Channel to check if the cycle is cancelled, before cleanup.
		doneChan := make(chan struct{})

		// Launch the fuzz worker scheduler as a goroutine.
		go scheduleFuzzing(schedulerCtx, logger, cfg, doneChan)

		// 3. Wait for either:
		//    A) All workers finish early
		//    B) SyncFrequency elapses
		//    C) Parent context cancellation
		select {
		case <-doneChan:
			logger.Info("All workers completed early; cleaning " +
				"up cycle")

			// Cancel the current cycle.
			cancelCycle()
			utils.CleanupWorkspace(logger, cfg)

		case <-time.After(cfg.Fuzz.SyncFrequency):
			logger.Info("Cycle duration complete; initiating " +
				"cleanup.")

			// Cancel the current cycle.
			cancelCycle()

			// wait before the fuzzing worker is closed before
			// cleanup.
			<-doneChan
			utils.CleanupWorkspace(logger, cfg)

		case <-ctx.Done():
			logger.Info("Shutdown initiated during fuzzing " +
				"cycle; performing final cleanup.")

			// Overall application context canceled.
			cancelCycle()

			// wait before the fuzzing worker is closed before
			// cleanup.
			<-doneChan
			utils.CleanupWorkspace(logger, cfg)

			return
		}
	}
}

// scheduleFuzzing enqueues all discovered fuzz targets into a task queue and
// spins up cfg.Fuzz.NumWorkers workers. Each worker runs until either:
//   - All tasks are completed.
//   - A worker returns an error (errgroup will cancel the others).
//   - The cycle context (ctx) is canceled.
//
// Returns an error if any worker fails.
func scheduleFuzzing(ctx context.Context, logger *slog.Logger, cfg *config.
	Config, doneChan chan struct{}) {

	defer close(doneChan)
	logger.Info("Starting fuzzing scheduler", "startTime", time.Now().
		Format(time.RFC1123))

	// Discover fuzz targets and build a task queue.
	taskQueue := worker.NewTaskQueue()
	for _, pkgPath := range cfg.Fuzz.PkgsPath {
		targets, err := fuzz.ListFuzzTargets(ctx, logger, cfg, pkgPath)
		if err != nil {
			logger.Error("Failed to list fuzz targets; aborting "+
				"scheduler", "package", pkgPath, "error", err)

			// Perform workspace cleanup before exiting due to the
			// list fuzz targets error.
			utils.CleanupWorkspace(logger, cfg)
			os.Exit(1)
		}
		// Enqueue all discovered fuzz targets.
		for _, target := range targets {
			taskQueue.Enqueue(worker.Task{
				PackagePath: pkgPath,
				Target:      target,
			})
		}
	}

	if taskQueue.Length() == 0 {
		logger.Warn("No fuzz targets found; aborting scheduler; " +
			"please add some fuzz targets")
		utils.CleanupWorkspace(logger, cfg)
		os.Exit(0)
	}

	// Calculate the fuzzing time for each fuzz target.
	fuzzSeconds := utils.CalculateFuzzSeconds(cfg.Fuzz.SyncFrequency,
		cfg.Fuzz.NumWorkers, taskQueue.Length())

	if fuzzSeconds <= 0 {
		logger.Error("invalid fuzz duration", "duration", fuzzSeconds)

		// Perform workspace cleanup before exiting due to the fuzz
		// duration error.
		utils.CleanupWorkspace(logger, cfg)
		os.Exit(1)
	}

	perTargetTimeout := time.Duration(fuzzSeconds) * time.Second

	logger.Info("Per-target fuzz timeout calculated", "duration",
		perTargetTimeout)

	// Make sure to cancel all workers if any single worker errors.
	g, workerCtx := errgroup.WithContext(ctx)
	for i := 1; i <= cfg.Fuzz.NumWorkers; i++ {
		workerID := i
		g.Go(func() error {
			return worker.RunWorker(workerID, workerCtx, taskQueue,
				perTargetTimeout, logger, cfg)
		})
	}

	// Wait for all workers to finish or for the first error/cancellation.
	if err := g.Wait(); err != nil {
		logger.Error("Fuzzing process failed", "error", err)

		// Perform workspace cleanup before exiting due to the fuzzing
		// error.
		utils.CleanupWorkspace(logger, cfg)
		os.Exit(1)
	}

	logger.Info("All fuzz targets processed successfully in this cycle")
}
