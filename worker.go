package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
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

// runWorker continuously pulls tasks from taskQueue and executes them via
// fuzz.executeFuzzTarget. Each Task is run with its own timeout (taskTimeout).
//
// If the worker context is canceled or any Task execution returns an error,
// runWorker stops and returns that error.
func runWorker(workerID int, workerCtx context.Context, taskQueue *TaskQueue,
	taskTimeout time.Duration, logger *slog.Logger, cfg *Config) error {

	for {
		task, ok := taskQueue.Dequeue()
		if !ok {
			logger.Info("No more tasks in queue; stopping worker",
				"workerID", workerID)
			return nil
		}

		logger.Info(
			"Worker starting fuzz target", "workerID", workerID,
			"package", task.PackagePath, "target", task.Target,
			"timeout", taskTimeout,
		)

		// Create a subcontext with timeout for this individual fuzz
		// target.
		taskCtx, cancel := context.WithTimeout(workerCtx, taskTimeout)
		err := executeFuzzTarget(taskCtx, logger, task.PackagePath,
			task.Target, cfg, taskTimeout)
		cancel()

		if err != nil {
			return fmt.Errorf("worker %d: fuzz target %q/%q "+
				"failed: %w", workerID, task.PackagePath,
				task.Target, err)
		}

		logger.Info(
			"Worker completed fuzz target", "workerID", workerID,
			"package", task.PackagePath, "target", task.Target,
		)
	}
}
