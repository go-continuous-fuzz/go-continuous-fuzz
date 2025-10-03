package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/docker/docker/client"
	"golang.org/x/sync/errgroup"
)

// Task represents a single fuzz target job, containing the package path and the
// specific target name to execute.
type Task struct {
	PackagePath string
	Target      string
}

// TaskQueue is a simple FIFO queue for scheduling Task items.
type TaskQueue struct {
	mu    sync.Mutex
	tasks []Task
}

// NewTaskQueue returns an empty, initialized TaskQueue.
func NewTaskQueue() *TaskQueue {
	return &TaskQueue{
		tasks: make([]Task, 0),
	}
}

// Enqueue adds a new Task to the back of the queue.
func (q *TaskQueue) Enqueue(t Task) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.tasks = append(q.tasks, t)
}

// Length returns the current number of tasks in the queue.
func (q *TaskQueue) Length() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	return len(q.tasks)
}

// Dequeue removes and returns the next Task from the queue. If the queue is
// empty, it returns false for the second return value.
func (q *TaskQueue) Dequeue() (Task, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.tasks) == 0 {
		return Task{}, false
	}
	t := q.tasks[0]
	q.tasks = q.tasks[1:]
	return t, true
}

// WorkerGroup manages a group of fuzzing workers, their context, logger, Docker
// client, configuration, shared task queue, per-task timeout, and if corpus
// should be minimized or not.
type WorkerGroup struct {
	ctx                  context.Context
	logger               *slog.Logger
	goGroup              *errgroup.Group
	cli                  *client.Client
	cfg                  *Config
	taskQueue            *TaskQueue
	taskTimeout          time.Duration
	shouldMinimizeCorpus bool
}

// WorkersStartAndWait starts the specified number of workers and waits for all
// to finish or for the first error/cancellation. Returns an error if any worker
// fails.
func (wg *WorkerGroup) WorkersStartAndWait(numWorkers int) error {
	for workerID := 1; workerID <= numWorkers; workerID++ {
		wg.goGroup.Go(func() error {
			return wg.runWorker(workerID)
		})
	}

	// Wait for all workers to finish or for the first error/cancellation.
	if err := wg.goGroup.Wait(); err != nil {
		return fmt.Errorf("one or more workers failed: %w", err)
	}

	return nil
}

// runWorker pulls tasks from the taskQueue until it is empty or the worker
// context is canceled:
//   - Verifies and close any resolved GitHub issues related to the fuzz target.
//   - Executes the fuzz target with a timeout.
func (wg *WorkerGroup) runWorker(workerID int) error {
	for {
		task, ok := wg.taskQueue.Dequeue()
		if !ok {
			wg.logger.Info("No more tasks in queue; stopping "+
				"worker", "workerID", workerID)
			return nil
		}

		wg.logger.Info(
			"Worker starting issue verification", "workerID",
			workerID, "package", task.PackagePath, "target",
			task.Target,
		)

		// Initialize a GitHub client for issue verification.
		gh, err := NewGitHubRepo(wg.ctx, wg.logger.With("target",
			task.Target).With("package", task.PackagePath), wg.cli,
			wg.cfg)
		if err != nil {
			return fmt.Errorf("error initializing GitHub client: "+
				"%w", err)
		}

		// The worker will verify and close any open GitHub issues
		// related to the fuzz target.
		err = gh.verifyAndCloseResolvedIssues(task.PackagePath,
			task.Target)
		if err != nil {
			if wg.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("failed to verify and close open "+
				"issues: %w", err)
		}

		wg.logger.Info(
			"Worker starting fuzzing", "workerID", workerID,
			"package", task.PackagePath, "target", task.Target,
			"timeout", wg.taskTimeout,
		)

		err = wg.executeFuzzTarget(task.PackagePath, task.Target, gh)
		if err != nil {
			if wg.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("worker %d: fuzz target %q/%q "+
				"failed: %w", workerID, task.PackagePath,
				task.Target, err)
		}

		wg.logger.Info(
			"Worker completed fuzz target", "workerID", workerID,
			"package", task.PackagePath, "target", task.Target,
		)
	}
}

// executeFuzzTarget runs the specified fuzz target for a package using Docker.
// It performs the following steps:
//   - Starts the fuzzing container and streams its output.
//   - Reports any fuzz crashes by creating a GitHub issue.
//   - Updates the coverage report.
//   - Optionally minimizes the corpus if configured.
func (wg *WorkerGroup) executeFuzzTarget(pkg string, target string,
	gh *GitHubRepo) error {

	wg.logger.Info("Executing fuzz target in Docker", "package", pkg,
		"target", target, "duration", wg.taskTimeout)

	// Construct the absolute path to the package directory within the
	// temporary project directory on the host machine.
	hostPkgPath := filepath.Join(wg.cfg.Project.SrcDir, pkg)

	// Define the path to store the corpus data generated during fuzzing on
	// the host machine.
	hostCorpusPath := filepath.Join(wg.cfg.Project.CorpusDir, pkg,
		"testdata", "fuzz")

	// Define the path to the fuzz target binary on the host machine that
	// will be executed inside the container.
	fuzzBinaryPath := filepath.Join(wg.cfg.Project.BinaryDir, pkg, target)

	// Ensure that the corpus directory on the host machine exists to avoid
	// permission errors when running the container as a non-root user.
	if err := EnsureDirExists(hostCorpusPath); err != nil {
		return err
	}

	// Prepare the arguments for the 'go test' command to run the specific
	// fuzz target in container.
	goTestCmd := []string{
		fmt.Sprintf("./%s.test", target),
		fmt.Sprintf("-test.fuzz=^%s$", target),
		fmt.Sprintf("-test.fuzzcachedir=%s", ContainerCorpusPath),
		"-test.parallel=1",
	}

	// Create a subcontext with timeout for this individual fuzz target.
	fuzzCtx, cancel := context.WithTimeout(wg.ctx, wg.taskTimeout+
		ContainerGracePeriod)
	defer cancel()

	c := &Container{
		ctx:            fuzzCtx,
		logger:         wg.logger,
		cli:            wg.cli,
		fuzzBinaryPath: fuzzBinaryPath,
		hostCorpusPath: hostCorpusPath,
		cmd:            goTestCmd,
	}

	// Start the fuzzing container.
	containerID, err := c.Start()
	if err != nil {
		if fuzzCtx.Err() != nil {
			return nil
		}
		return fmt.Errorf("error while starting container: %w", err)
	}
	defer c.Stop(containerID)

	// Channels to receive either a fuzz failure or a container error.
	fuzzCrashChan := make(chan fuzzCrash, 1)
	errorChan := make(chan error, 1)

	// Begin processing logs and wait for completion/failure signal in a
	// goroutine.
	go c.WaitAndGetLogs(containerID, pkg, target, fuzzCrashChan, errorChan)

	select {
	case <-fuzzCtx.Done():
		// Context timeout or cancellation occurred.

	case err := <-errorChan:
		if err != nil {
			// Container exited with an error (non-fuzz crash).
			return fmt.Errorf("fuzz execution failed: %w", err)
		}

	case fuzzCrash := <-fuzzCrashChan:
		// Report the fuzz crash.
		if err := gh.handleCrash(pkg, target, fuzzCrash); err != nil {
			return fmt.Errorf("handling fuzz crash: %w", err)
		}
	}

	wg.logger.Info("Fuzzing in Docker completed successfully", "package",
		pkg, "target", target)

	err = updateReport(wg.ctx, pkg, target, wg.cfg, wg.logger)
	if err != nil {
		return fmt.Errorf("failed to add coverage report for package "+
			"%s, target %s: %w", pkg, target, err)
	}

	wg.logger.Info("Successfully added/updated coverage report", "package",
		pkg, "target", target)

	// Minimize the corpus if needed.
	if wg.shouldMinimizeCorpus {
		err := MinimizeCorpus(wg.ctx, wg.logger.With("target", target).
			With("package", pkg), hostPkgPath, hostCorpusPath,
			target)
		if err != nil {
			return fmt.Errorf("minimizing corpus for target %q: %w",
				target, err)
		}
	}

	return nil
}
