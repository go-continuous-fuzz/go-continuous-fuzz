package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/go-git/go-git/v5"
	"golang.org/x/sync/errgroup"
)

// runFuzzingCycles runs an infinite loop of fuzzing cycles. Each cycle consists
// of:
//  1. Cloning the Git repository specified in cfg.Project.SrcRepo.
//  2. Downloading corpus from S3 bucket specified in cfg.Project.S3BucketName.
//  3. Launching scheduler goroutines to execute all fuzz targets for a portion
//     of cfg.Fuzz.SyncFrequency.
//  4. Cleaning up the workspace.
//  5. Uploading the updated corpus to the S3 bucket.
//
// The loop repeats until the parent context is canceled. Errors in cloning or
// target discovery are returned immediately.
func runFuzzingCycles(ctx context.Context, logger *slog.Logger,
	cfg *Config) error {

	for {
		// Cleanup the project and corpus directory (if any) created
		// during previous runs.
		cleanupProjectAndCorpus(logger, cfg)

		// 1. Clone the repository based on the provided configuration.
		logger.Info("Cloning project repository", "url",
			SanitizeURL(cfg.Project.SrcRepo), "path",
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

		// 2. Download corpus from S3 bucket.
		s3cs, err := NewS3CorpusStore(ctx, logger, cfg)
		if err != nil {
			logger.Error("Failed to create S3 client; aborting" +
				"scheduler")
			return err
		}

		if err := s3cs.downloadUnZipCorpus(); err != nil {
			logger.Error("Failed to download and unzip corpus; " +
				"aborting scheduler")
			return err
		}

		// 3. Create a scheduler context for this fuzz iteration.
		schedulerCtx, cancelCycle := context.WithCancel(ctx)

		// Channel to report any error that occurs during the cycle.
		errChan := make(chan error, 1)

		// Launch the fuzz worker scheduler as a goroutine.
		go scheduleFuzzing(schedulerCtx, logger, cfg, errChan)

		// Set up the grace period for all workers to finish their
		// tasks.
		gracePeriod := min(cfg.Fuzz.SyncFrequency/5, 1*time.Hour)

		// 4. Wait for either:
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

		// 5. Only upload the updated corpus if the cycle succeeded.
		if err := s3cs.zipUploadCorpus(); err != nil {
			logger.Error("Failed to zip and upload corpus; " +
				"aborting scheduler")
			return err
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
func scheduleFuzzing(ctx context.Context, logger *slog.Logger, cfg *Config,
	errChan chan error) {

	logger.Info("Starting fuzzing scheduler", "startTime", time.Now().
		Format(time.RFC1123))

	// Discover fuzz targets and build a task queue.
	taskQueue := NewTaskQueue()
	for _, pkgPath := range cfg.Fuzz.PkgsPath {
		targets, err := listFuzzTargets(ctx, logger, cfg, pkgPath)
		if err != nil {
			logger.Error("Failed to list fuzz targets", "package",
				pkgPath)
			errChan <- err
			return
		}
		// Enqueue all discovered fuzz targets.
		for _, target := range targets {
			taskQueue.Enqueue(Task{
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
	perTargetTimeout := calculateFuzzSeconds(cfg.Fuzz.SyncFrequency,
		cfg.Fuzz.NumWorkers, taskQueue.Length())

	if perTargetTimeout == 0 {
		errChan <- fmt.Errorf("invalid fuzz duration: %s",
			perTargetTimeout)
		return
	}

	logger.Info("Per-target fuzz timeout calculated", "duration",
		perTargetTimeout)

	// Create a Docker client for running containers.
	cli, err := client.NewClientWithOpts(client.FromEnv,
		client.WithAPIVersionNegotiation())
	if err != nil {
		errChan <- fmt.Errorf("failed to start docker client: %w", err)
		return
	}
	defer func() {
		if err := cli.Close(); err != nil {
			logger.Error("Failed to stop docker client", "error",
				err)
		}
	}()

	// Pull the Docker image specified by ContainerImage ("golang:1.23.9").
	reader, err := cli.ImagePull(ctx, ContainerImage,
		image.PullOptions{})
	if err != nil {
		errChan <- fmt.Errorf("failed to pull docker image: %w", err)
		return
	}
	defer func() {
		err := reader.Close()
		if err != nil {
			logger.Error("Failed to close image logs reader",
				"error", err)
		}
	}()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		logger.Info("Image Pull output", "message", line)
	}
	if err := scanner.Err(); err != nil {
		errChan <- fmt.Errorf("error reading image-pull stream: %w",
			err)
		return
	}

	// Make sure to cancel all workers if any single worker errors.
	g, workerCtx := errgroup.WithContext(ctx)
	wg := &WorkerGroup{
		ctx:         workerCtx,
		logger:      logger,
		goGroup:     g,
		cli:         cli,
		cfg:         cfg,
		taskQueue:   taskQueue,
		taskTimeout: perTargetTimeout,
	}

	// Start and wait for all workers to finish or for the first
	// error/cancellation.
	if err := wg.WorkersStartAndWait(cfg.Fuzz.NumWorkers); err != nil {
		errChan <- fmt.Errorf("fuzzing process failed: %w", err)
		return
	}

	logger.Info("All fuzz targets processed successfully in this cycle")
	errChan <- nil
}

// listFuzzTargets discovers and returns a list of fuzz targets for the given
// package. It uses "go test -list=^Fuzz" to list the functions and filters
// those that start with "Fuzz".
func listFuzzTargets(ctx context.Context, logger *slog.Logger, cfg *Config,
	pkg string) ([]string, error) {

	logger.Info("Discovering fuzz targets", "package", pkg)

	// Construct the absolute path to the package directory within the
	// temporary project directory.
	pkgPath := filepath.Join(cfg.Project.SrcDir, pkg)

	// Prepare the command to list all test functions matching the pattern
	// "^Fuzz". This leverages go's testing tool to identify fuzz targets.
	cmd := exec.CommandContext(ctx, "go", "test", "-list=^Fuzz", ".")

	// Set the working directory to the package path.
	cmd.Dir = pkgPath

	// Initialize buffers to capture standard output and standard error from
	// the command execution.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command and check for errors, when the context wasn't
	// canceled.
	if err := cmd.Run(); err != nil && ctx.Err() == nil {
		return nil, fmt.Errorf("go test failed for %q: %w (output: %q)",
			pkg, err, strings.TrimSpace(stderr.String()))
	}

	// targets holds the names of discovered fuzz targets.
	var targets []string

	// Process each line of the command's output.
	for _, line := range strings.Split(stdout.String(), "\n") {
		cleanLine := strings.TrimSpace(line)
		if strings.HasPrefix(cleanLine, "Fuzz") {
			// If the line represents a fuzz target, add it to the
			// list.
			targets = append(targets, cleanLine)
		}
	}

	// If no fuzz targets are found, log a warning to inform the user.
	if len(targets) == 0 {
		logger.Warn("No valid fuzz targets found", "package", pkg)
	}

	return targets, nil
}
