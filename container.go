package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// Container encapsulates the configuration and state needed to manage a Docker
// container for running fuzzing tasks, including context, logger, Docker client
// configuration, working directories, and command.
type Container struct {
	ctx            context.Context
	logger         *slog.Logger
	cli            *client.Client
	cfg            *Config
	workDir        string
	hostCorpusPath string
	cmd            []string
}

// Start creates and starts a Docker container with the specified configuration.
// It returns the container ID if successful, or an error if container creation
// or startup fails.
func (c *Container) Start() (string, error) {
	// Prepare Docker container configuration and limit resources for the
	// container.
	containerConfig := &container.Config{
		Image:        ContainerImage,
		Cmd:          c.cmd,
		WorkingDir:   c.workDir,
		User:         fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
		Env: []string{
			"GOCACHE=/tmp",
		},
	}
	hostConfig := &container.HostConfig{
		AutoRemove: true,
		Binds: []string{
			fmt.Sprintf("%s:%s", c.cfg.Project.SrcDir,
				ContainerProjectPath),
			fmt.Sprintf("%s:%s", c.hostCorpusPath,
				ContainerCorpusPath),
		},
		Resources: container.Resources{
			Memory:   2 * 1024 * 1024 * 1024,
			NanoCPUs: 1_000_000_000,
		},
	}

	resp, err := c.cli.ContainerCreate(c.ctx, containerConfig, hostConfig,
		nil, nil, "")
	if err != nil {
		return "",
			fmt.Errorf("failed to create fuzz container: %w", err)
	}

	if err := c.cli.ContainerStart(c.ctx, resp.ID,
		container.StartOptions{}); err != nil {
		return "",
			fmt.Errorf("failed to start fuzz container: %w", err)
	}

	return resp.ID, nil
}

// WaitAndGetLogs listens to the container's log stream, processes fuzz output,
// and reports either a fuzz crash or the container's exit status.
//
// It reads logs until EOF or context cancellation, then:
// 1. If a fuzz failure is detected, sends true on failingChan.
// 2. Otherwise, retrieves the container's exit error and sends it on errChan.
//
// No values are sent if the context is canceled or times out.
//
//	This MUST be run as a goroutine.
func (c *Container) WaitAndGetLogs(ID, pkg, target string,
	failingChan chan bool, errChan chan error) {

	// Acquire the log stream (stdout + stderr) for the running container.
	logsReader, err := c.cli.ContainerLogs(c.ctx, ID,
		container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,
			Timestamps: false,
		})
	if err != nil {
		if c.ctx.Err() == nil {
			errChan <- fmt.Errorf("unable to attach to logs for "+
				"container %s: %w", ID, err)
		}
		return
	}
	defer func() {
		if err := logsReader.Close(); err != nil {
			c.logger.Error("error closing logs reader", "container",
				ID, "error", err)
		}
	}()

	// Define the path where failing corpus inputs might be saved by the
	// fuzzing process.
	maybeFailingCorpusPath := filepath.Join(c.cfg.Project.SrcDir, pkg,
		"testdata", "fuzz")

	// Process the standard output, which may include both stdout and stderr
	// content.
	processor := NewFuzzOutputProcessor(c.logger.With("target", target).
		With("package", pkg), c.cfg, maybeFailingCorpusPath, pkg,
		target)
	crashed := processor.processFuzzStream(logsReader)

	// Fuzz target crashed: notify via failingChan.
	if crashed {
		failingChan <- true
		return
	}

	// Retrieve the container's exit status and send error (if any) on
	// errChan.
	errChan <- c.Wait(ID)
}

// Wait waits for the specified Docker container to finish execution. It returns
// an error if the container exits with a non-zero status or if there is an
// error waiting for the container to finish.
func (c *Container) Wait(ID string) error {
	// Wait for the container to finish.
	statusCh, errCh := c.cli.ContainerWait(c.ctx, ID,
		container.WaitConditionNotRunning)

	select {
	case err := <-errCh:
		if c.ctx.Err() == nil {
			return fmt.Errorf("error waiting for fuzz container: "+
				"%w", err)
		}
	case status := <-statusCh:
		if status.StatusCode != 0 {
			return fmt.Errorf("fuzz container exited with "+
				"status %d", status.StatusCode)
		}
	}

	return nil
}

// Stop attempts to gracefully stop the specified Docker container by its ID.
// After a default timeout of 10 seconds, the container is forcefully killed.
func (c *Container) Stop(ID string) {
	if err := c.cli.ContainerStop(context.Background(), ID,
		container.StopOptions{}); err != nil {
		c.logger.Error("Failed to stop container", "error", err,
			"containerID", ID)
	}
}
