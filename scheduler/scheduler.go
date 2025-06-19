package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/fuzz"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/utils"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/worker"
	"github.com/go-git/go-git/v5"
	"golang.org/x/sync/errgroup"
)

// RunFuzzingCycles runs an infinite loop of fuzzing cycles. Each cycle consists
// of:
//  1. Cloning the Git repository specified in cfg.Project.SrcRepo.
//  2. Launching scheduler goroutines to execute all fuzz targets for a portion
//     of cfg.Fuzz.SyncFrequency.
//  3. Cleaning up the workspace.
//
// The loop repeats until the parent context is canceled. Errors in cloning or
// target discovery are returned immediately.
func RunFuzzingCycles(ctx context.Context, logger *slog.Logger, cfg *config.
	Config) error {

	for {
		// Cleanup the project directory (if any) created during
		// previous runs.
		utils.CleanupProject(logger, cfg)

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
			logger.Error("Failed to clone project repository; " +
				"aborting scheduler")
			return err
		}

		// 2. Create a scheduler context for this fuzz iteration.
		schedulerCtx, cancelCycle := context.WithCancel(ctx)

		// Channel to report any error that occurs during the cycle.
		errChan := make(chan error, 1)

		// Launch the fuzz worker scheduler as a goroutine.
		go scheduleFuzzing(schedulerCtx, logger, cfg, errChan)

		// Set up the grace period for all workers to finish their
		// tasks.
		gracePeriod := min(cfg.Fuzz.SyncFrequency/10, 1*time.Hour)

		// 3. Wait for either:
		//    A) All workers finish early
		//    B) SyncFrequency elapses
		//    C) Parent context cancellation
		//    D) An error occurs
		select {
		case <-time.After(cfg.Fuzz.SyncFrequency + gracePeriod):
			// Cancel the current cycle.
			cancelCycle()

			// wait before the fuzzing scheduler is closed.
			if err := <-errChan; err != nil {
				logger.Error("Fuzzing cycle failed; aborting " +
					"scheduler")
				return err
			}
			logger.Info("Cycle duration complete; initiating " +
				"cleanup.")

		case <-ctx.Done():
			// Overall application context canceled.
			cancelCycle()

			logger.Info("Shutdown initiated during fuzzing " +
				"cycle; performing final cleanup.")

			return <-errChan

		case err := <-errChan:
			// Cancel the current cycle.
			cancelCycle()

			if err != nil {
				logger.Error("Fuzzing cycle failed; aborting " +
					"scheduler")
				return err
			}
			logger.Info("All workers completed early; cleaning " +
				"up cycle")
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
	Config, errChan chan error) {

	logger.Info("Starting fuzzing scheduler", "startTime", time.Now().
		Format(time.RFC1123))

	// Discover fuzz targets and build a task queue.
	taskQueue := worker.NewTaskQueue()
	for _, pkgPath := range cfg.Fuzz.PkgsPath {
		targets, err := fuzz.ListFuzzTargets(ctx, logger, cfg, pkgPath)
		if err != nil {
			logger.Error("Failed to list fuzz targets", "package",
				pkgPath)
			errChan <- err
			return
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
		errChan <- fmt.Errorf("No fuzz targets found; please add " +
			"some fuzz targets.")
		return
	}

	// Calculate the fuzzing time for each fuzz target.
	perTargetTimeout := utils.CalculateFuzzSeconds(cfg.Fuzz.SyncFrequency,
		cfg.Fuzz.NumWorkers, taskQueue.Length())

	if perTargetTimeout == 0 {
		errChan <- fmt.Errorf("invalid fuzz duration: %s",
			perTargetTimeout)
		return
	}

	logger.Info("Per-target fuzz timeout calculated", "duration",
		perTargetTimeout)

	// Make sure to cancel all workers if any single worker errors.
	g, workerCtx := errgroup.WithContext(ctx)
	for workerID := 1; workerID <= cfg.Fuzz.NumWorkers; workerID++ {
		g.Go(func() error {
			return worker.RunWorker(workerID, workerCtx, taskQueue,
				perTargetTimeout, logger, cfg)
		})
	}

	// Wait for all workers to finish or for the first error/cancellation.
	if err := g.Wait(); err != nil {
		errChan <- fmt.Errorf("fuzzing process failed: %w", err)
		return
	}

	logger.Info("All fuzz targets processed successfully in this cycle")
	errChan <- nil
}
