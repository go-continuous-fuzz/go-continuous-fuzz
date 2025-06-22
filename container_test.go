package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
)

// TestContainerRaceAndTimeout verifies that the Docker client is safe for
// concurrent use by launching two containers at the same time. It also checks
// that if both containers are set to run indefinitely, applying a context
// timeout will stop them early, and that the total duration of each container's
// lifecycle stays within the timeout limit.
func TestContainerRaceAndTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Create a temporary workspace for container mounts.
	tmpDir := t.TempDir()

	// Set up Docker client for running containers.
	cli, err := client.NewClientWithOpts(client.FromEnv,
		client.WithAPIVersionNegotiation())
	assert.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, cli.Close()) })

	// Pull the golang:1.23.9 image once for both containers.
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

			start := time.Now()
			c := &Container{
				ctx:             taskCtx,
				cli:             cli,
				workDir:         tmpDir,
				hostProjectPath: tmpDir,
				hostCorpusPath:  tmpDir,
				cmd:             []string{"sleep", "infinity"},
			}

			id, logs, err := c.Start()
			assert.NoError(t, err)

			// Ensure container stop and log reader close happen as
			// soon as this test exits.
			defer func() {
				assert.NoError(t, c.cli.ContainerStop(
					context.Background(), id,
					container.StopOptions{}))
				assert.NoError(t, logs.Close())
			}()

			// Since reading from logs is blocking, the context
			// deadline will expire and only a context deadline
			// error should be returned.
			if _, err := io.Copy(io.Discard, logs); err != nil {
				if !errors.Is(err, context.Canceled) &&
					!errors.Is(err,
						context.DeadlineExceeded) {

					assert.NoError(t, err)
				}
			}

			if err := c.Wait(id); err != nil {
				if !errors.Is(err, context.Canceled) &&
					!errors.Is(err,
						context.DeadlineExceeded) {

					assert.NoError(t, err)
				}
			}

			// Verify the elapsed time is within 1s of the timeout.
			elapsed := time.Since(start)
			assert.InDelta(t, timeout.Seconds(), elapsed.Seconds(),
				1.0)
		})
	}
}
