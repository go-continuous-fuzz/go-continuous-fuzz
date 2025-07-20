package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/client"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
)

// FuzzRunner abstracts Kubernetes or Docker fuzz execution
type FuzzRunner interface {
	Start() (string, error)
	Stop(ID string)
	WaitAndGetLogs(ID string, pkg string, target string,
		fuzzCrashChan chan fuzzCrash, errChan chan error)
}

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
// or Kubernetes client, configuration, shared task queue, and per-task timeout.
type WorkerGroup struct {
	ctx          context.Context
	logger       *slog.Logger
	goGroup      *errgroup.Group
	dockerClient *client.Client
	k8sClientSet *kubernetes.Clientset
	cfg          *Config
	taskQueue    *TaskQueue
	taskTimeout  time.Duration
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

// runWorker continuously pulls tasks from taskQueue and executes them via
// fuzz.executeFuzzTarget. Each Task is run with its own timeout (taskTimeout).
//
// If the worker context is canceled or any Task execution returns an error,
// runWorker stops and returns that error.
func (wg *WorkerGroup) runWorker(workerID int) error {
	for {
		task, ok := wg.taskQueue.Dequeue()
		if !ok {
			wg.logger.Info("No more tasks in queue; stopping "+
				"worker", "workerID", workerID)
			return nil
		}

		wg.logger.Info(
			"Worker starting fuzz target", "workerID", workerID,
			"package", task.PackagePath, "target", task.Target,
			"timeout", wg.taskTimeout,
		)

		err := wg.executeFuzzTarget(task.PackagePath, task.Target)
		if err != nil {
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

// executeFuzzTarget runs the specified fuzz target for a package for a given
// duration using either Kubernetes (in-cluster) or Docker. It handles
// environment setup, execution, log streaming, creates a GitHub issue
// reporting the crash (if any), and updates the coverage report.
func (wg *WorkerGroup) executeFuzzTarget(pkg string, target string) error {
	// Determine execution environment
	mode := "Docker"
	if wg.cfg.Fuzz.InCluster {
		mode = "Kubernetes"
	}
	wg.logger.Info("Executing fuzz target", "mode", mode, "package", pkg,
		"target", target, "duration", wg.taskTimeout)

	// Construct the absolute path to the package directory within the
	// temporary project directory.
	pkgPath := filepath.Join(wg.cfg.Project.SrcDir, pkg)

	// Define the path to store the corpus data generated during fuzzing.
	corpusPath := filepath.Join(wg.cfg.Project.CorpusDir, pkg, "testdata",
		"fuzz")

	// Ensure that the corpus directory exists to avoid permission errors
	// when running the container/pod as a non-root user.
	if err := EnsureDirExists(corpusPath); err != nil {
		return err
	}

	// Create a subcontext with timeout for this individual fuzz target.
	fuzzCtx, cancel := context.WithTimeout(wg.ctx, wg.taskTimeout+
		FuzzGracePeriod)
	defer cancel()

	// Prepare runner configuration.
	runner := wg.createFuzzRunner(fuzzCtx, pkg, target, pkgPath, corpusPath)

	// Start the fuzzing runner.
	fuzzID, err := runner.Start()
	if err != nil {
		if fuzzCtx.Err() != nil {
			return nil
		}
		return fmt.Errorf("failed to start fuzz runner: %w", err)
	}
	defer runner.Stop(fuzzID)

	// Channels to receive either a fuzz failure or a runner error.
	fuzzCrashChan := make(chan fuzzCrash, 1)
	errorChan := make(chan error, 1)

	// Begin processing logs and wait for completion/failure signal in a
	// goroutine.
	go runner.WaitAndGetLogs(fuzzID, pkg, target, fuzzCrashChan, errorChan)

	select {
	case <-fuzzCtx.Done():
		// Context timeout or cancellation occurred.

	case err := <-errorChan:
		if err != nil {
			// Container exited with an error (non-fuzz crash).
			return fmt.Errorf("fuzz execution failed: %w", err)
		}

	case fuzzCrash := <-fuzzCrashChan:
		// Create a GitHub client and report the fuzz crash.
		gh, err := NewGitHubRepo(wg.ctx, wg.logger.With("target",
			target).With("package", pkg), wg.cfg.Fuzz.CrashRepo)
		if err != nil {
			return fmt.Errorf("initializing GitHub client: %w", err)
		}

		if err := gh.handleCrash(pkg, target, fuzzCrash); err != nil {
			if wg.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("handling fuzz crash: %w", err)
		}

		// If the fuzz target fails, 'go test' saves the failing input
		// in the package's testdata/fuzz/<FuzzTestName> directory. To
		// prevent these saved inputs from causing subsequent test runs
		// to fail (especially when running other fuzz targets), we
		// remove the testdata directory to clean up the failing inputs.
		failingInputPath := filepath.Join(pkgPath, "testdata", "fuzz",
			target)
		if err := os.RemoveAll(failingInputPath); err != nil {
			return fmt.Errorf("failing input cleanup failed: %w",
				err)
		}
	}

	wg.logger.Info("Fuzzing completed successfully", "mode", mode,
		"package", pkg, "target", target)

	err = updateReport(wg.ctx, pkg, target, wg.cfg, wg.logger)
	if err != nil {
		if wg.ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("failed to add coverage report for package "+
			"%s, target %s: %w", pkg, target, err)
	}

	wg.logger.Info("Successfully added/updated coverage report", "package",
		pkg, "target", target)

	return nil
}

// createFuzzRunner initializes the appropriate fuzzing runner (either
// Kubernetes job or Docker container) based on the execution mode.
func (wg *WorkerGroup) createFuzzRunner(ctx context.Context, pkg, target,
	pkgPath, corpusPath string) FuzzRunner {

	// Prepare the base arguments for the 'go test' command to run the
	// specific fuzz target in container/pod.
	cmd := []string{
		"go", "test",
		fmt.Sprintf("-fuzz=^%s$", target),
		"-parallel=1",
	}

	// Append fuzz cache directory path depending on the mode
	if wg.cfg.Fuzz.InCluster {
		cmd = append(cmd, fmt.Sprintf("-test.fuzzcachedir=%s",
			corpusPath))
		return &K8sJob{
			ctx:    ctx,
			logger: wg.logger,
			jobName: strings.ToLower(fmt.Sprintf("fuzz-job-%s-%s",
				pkg, target)),
			clientset: wg.k8sClientSet,
			cfg:       wg.cfg,
			workDir:   pkgPath,
			cmd:       cmd,
		}
	}

	cmd = append(cmd, fmt.Sprintf("-test.fuzzcachedir=%s",
		ContainerCorpusPath))
	return &Container{
		ctx:            ctx,
		logger:         wg.logger,
		cli:            wg.dockerClient,
		cfg:            wg.cfg,
		workDir:        filepath.Join(ContainerProjectPath, pkg),
		hostCorpusPath: corpusPath,
		cmd:            cmd,
	}
}
