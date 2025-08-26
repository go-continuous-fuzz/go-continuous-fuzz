package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
)

// TestContainerRace verifies that the Docker client is safe for concurrent use
// by launching two containers in parallel. It ensures that concurrent
// operations on a shared Docker client do not cause data races or unexpected
// errors.
func TestContainerRace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Create a temporary workspace for container mounts.
	tmpDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Set up Docker client for running containers.
	cli, err := client.NewClientWithOpts(client.FromEnv,
		client.WithAPIVersionNegotiation())
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, cli.Close()) })

	// Pull the golang image once for both containers.
	reader, err := cli.ImagePull(ctx, ContainerImage,
		image.PullOptions{})
	assert.NoError(t, err)

	_, err = io.Copy(io.Discard, reader)
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, reader.Close()) })

	const timeout = 15 * time.Second

	// Run two containers concurrently to test for races.
	for i := 1; i <= 2; i++ {
		t.Run(fmt.Sprintf("container-%d", i), func(t *testing.T) {
			t.Parallel()

			taskCtx, taskCancel := context.WithTimeout(ctx, timeout)
			defer taskCancel()

			c := &Container{
				ctx:            taskCtx,
				logger:         logger,
				cli:            cli,
				fuzzBinaryPath: tmpDir,
				hostCorpusPath: tmpDir,
				cmd:            []string{"sleep", "infinity"},
			}

			id, err := c.Start()
			assert.NoError(t, err)
			defer c.Stop(id)

			errorChan := make(chan error, 1)

			// Start processing logs and wait for completion/failure
			// signal in a goroutine.
			go c.WaitAndGetLogs(id, "", "", nil, errorChan)

			select {
			case <-taskCtx.Done():
				// This is the expected path: the context
				// timeout.

			case err := <-errorChan:
				assert.NoError(t, err)
			}
		})
	}
}
