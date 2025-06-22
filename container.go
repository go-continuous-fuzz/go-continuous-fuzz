package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// Container encapsulates the configuration and state needed to manage a Docker
// container for running fuzzing tasks, including context, logger, Docker client
// working directories, and command.
type Container struct {
	ctx             context.Context
	logger          *slog.Logger
	cli             *client.Client
	workDir         string
	hostProjectPath string
	hostCorpusPath  string
	cmd             []string
}

// Start creates a Docker container with the specified configuration, starts it,
// and attaches to its logs. It returns the container ID and a reader for the
// container's combined stdout and stderr output.
func (c *Container) Start() (string, io.ReadCloser, error) {
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
			fmt.Sprintf("%s:%s", c.hostProjectPath,
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
		return "", nil,
			fmt.Errorf("failed to create fuzz container: %w", err)
	}

	if err := c.cli.ContainerStart(c.ctx, resp.ID,
		container.StartOptions{}); err != nil {
		return "", nil,
			fmt.Errorf("failed to start fuzz container: %w", err)
	}

	// Attach to logs after starting container
	logsReader, err := c.cli.ContainerLogs(c.ctx, resp.ID,
		container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,
			Timestamps: false,
		})
	if err != nil {
		return resp.ID, nil,
			fmt.Errorf("failed to attach to container logs: %w",
				err)
	}

	return resp.ID, logsReader, nil
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
		return fmt.Errorf("error waiting for fuzz container: %w", err)
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
