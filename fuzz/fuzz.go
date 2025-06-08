package fuzz

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/parser"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/utils"
	"golang.org/x/sync/errgroup"
)

// RunFuzzing iterates over the configured fuzz packages and executes all
// fuzz targets found in each package. It spawns parallel goroutines for each
// target but will cease launching new work as soon as the context is canceled.
func RunFuzzing(ctx context.Context, logger *slog.Logger,
	cfg *config.Config) error {

	// Create an errgroup that shares this context. Any error or
	// cancellation will cancel all in-flight fuzz runs.
	g, goCtx := errgroup.WithContext(ctx)

	// Loop over each package the user requested fuzzing for.
	for _, pkg := range cfg.Fuzz.PkgsPath {
		pkg := pkg // capture loop variable

		// Run fuzzing for each package in a separate goroutine.
		g.Go(func() error {
			// Before starting work, check if we've been asked to
			// stop.
			select {
			case <-ctx.Done():
				// Context canceled: stop processing further
				// packages.
				return nil
			case <-goCtx.Done():
				// error already encountered: stop processing
				// further
				return nil
			default:
				// Context still active: proceed to list and run
				// fuzz targets.
			}

			// Discover all fuzz targets in this package (pkg)
			targets, err := listFuzzTargets(goCtx, logger, pkg)
			if err != nil {
				return fmt.Errorf("failed to list targets for"+
					" package %q: %w", pkg, err)
			}

			for _, target := range targets {
				// Capture loop variables for closure
				pkg := pkg
				target := target

				// Launch each fuzz target in a separate
				// goroutine. If an error other than a fuzz
				// target failure occurs during execution, it is
				// returned and will cause the errgroup to
				// cancel all other running goroutines.
				g.Go(func() error {
					// Before starting work, check if we've
					// been asked to stop.
					select {
					case <-ctx.Done():
						// Context canceled: stop
						// processing further packages.
						return nil
					case <-goCtx.Done():
						// error already encountered:
						// stop processing further
						return nil
					default:
						// Context still active: proceed
						// to list and run fuzz targets.
					}

					if err := executeFuzzTarget(goCtx,
						logger, pkg, target,
						cfg); err != nil {
						return fmt.Errorf("fuzzing "+
							"failed for %q/%q: %w",
							pkg, target, err)
					}
					return nil
				})
			}
			return nil
		})
	}

	// Wait for all fuzz target executions to finish or any to error/cancel.
	if err := g.Wait(); err != nil {
		return fmt.Errorf("error during fuzzing: %w", err)
	}

	return nil
}

// listFuzzTargets discovers and returns a list of fuzz targets for the given
// package. It uses "go test -list=^Fuzz" to list the functions and filters
// those that start with "Fuzz".
func listFuzzTargets(ctx context.Context, logger *slog.Logger,
	pkg string) ([]string, error) {

	logger.Info("Discovering fuzz targets", "package", pkg)

	// Construct the absolute path to the package directory within the
	// default project directory.
	pkgPath := filepath.Join(config.DefaultProjectDir, pkg)

	// Prepare the command to list all test functions matching the pattern
	// "^Fuzz". This leverages Go's testing tool to identify fuzz targets.
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

// executeFuzzTarget runs the specified fuzz target for a package using the
// "go test" command. It sets up the necessary environment, starts the command,
// streams its output and log the failure (if any) in the log file.
func executeFuzzTarget(ctx context.Context, logger *slog.Logger, pkg string,
	target string, cfg *config.Config) error {

	logger.Info("Executing fuzz target", "package", pkg, "target", target)

	// Construct the absolute path to the package directory within the
	// default project directory.
	pkgPath := filepath.Join(config.DefaultProjectDir, pkg)

	// Retrieve the current working directory.
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	// Define the path to store the corpus data generated during fuzzing.
	corpusPath := filepath.Join(
		cwd, config.DefaultCorpusDir, pkg, "testdata", "fuzz",
	)

	// Define the path where failing corpus inputs might be saved by the
	// fuzzing process.
	maybeFailingCorpusPath := filepath.Join(pkgPath, "testdata", "fuzz")

	// Prepare the arguments for the 'go test' command to run the specific
	// fuzz target.
	args := []string{
		"test",
		fmt.Sprintf("-fuzz=^%s$", target),
		fmt.Sprintf("-test.fuzzcachedir=%s", corpusPath),
		fmt.Sprintf("-fuzztime=%s", cfg.Fuzz.Time),
		fmt.Sprintf("-parallel=%d", cfg.Fuzz.NumProcesses),
	}

	// Initialize the 'go test' command with the specified arguments and
	// context.
	cmd := exec.CommandContext(ctx, "go", args...)
	// Set the working directory for the command.
	cmd.Dir = pkgPath

	// Obtain a pipe to read the standard output of the command.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe failed: %w", err)
	}

	// Start the execution of the 'go test' command.
	if err := cmd.Start(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("command start failed: %w", err)
	}

	// Channel to signal if the fuzz target encountered a failure.
	fuzzTargetFailingChan := make(chan bool, 1)

	var wg sync.WaitGroup
	wg.Add(1)

	// Stream and process the standard output of 'go test', which may
	// include both stdout and stderr content.
	go streamFuzzOutput(logger.With("target", target).With("package", pkg),
		&wg, stdout, maybeFailingCorpusPath, cfg, target,
		fuzzTargetFailingChan)

	// Wait for the output streaming to complete.
	wg.Wait()

	// Wait for the 'go test' command to finish execution.
	err = cmd.Wait()

	// Check if the fuzz target encountered a failure.
	isFailing := <-fuzzTargetFailingChan

	// Proceed to return an error only if the fuzz target did not fail
	// (i.e., no failure was detected during fuzzing), and the command
	// execution resulted in an error, and the error is not due to a
	// cancellation of the context.
	if err != nil {
		if ctx.Err() == nil && !isFailing {
			return fmt.Errorf("fuzz execution failed: %w", err)
		}
	}

	// If the fuzz target fails, 'go test' saves the failing input in the
	// package's testdata/fuzz/<FuzzTestName> directory. To prevent these
	// saved inputs from causing subsequent test runs to fail (especially
	// when running other fuzz targets), we remove the testdata directory to
	// clean up the failing inputs.
	if isFailing {
		failingInputPath := filepath.Join(pkgPath, "testdata", "fuzz",
			target)
		if err := os.RemoveAll(failingInputPath); err != nil {
			return fmt.Errorf("failing input cleanup failed: %w",
				err)
		}
	}

	logger.Info("Fuzzing completed successfully", "package", pkg,
		"target", target,
	)

	// If fuzzing was successful, save the corpus data to the specified
	// directory.
	utils.SaveFuzzCorpus(logger, cfg, pkg, target)

	return nil
}

// streamFuzzOutput reads and processes the standard output of a fuzzing
// process. It utilizes a FuzzOutputProcessor to parse each line of output,
// identifying any errors or failures that occur during fuzzing. If a failure is
// detected, it logs the error details and the corresponding failing test case
// into the log file for analysis. The function signals completion through the
// provided WaitGroup and communicates whether a failure was encountered via the
// fuzzTargetFailingChan channel.
func streamFuzzOutput(logger *slog.Logger, wg *sync.WaitGroup, r io.Reader,
	corpusPath string, cfg *config.Config, target string,
	failureChan chan bool) {

	defer wg.Done()

	// Create a FuzzOutputProcessor to handle parsing and logging of fuzz
	// output.
	processor := parser.NewFuzzOutputProcessor(logger, cfg, corpusPath,
		target)

	// Process the fuzzing output stream. This will log all output, detect
	// failures, and write failure details to disk if encountered.
	failureDetected := processor.ProcessFuzzStream(r)

	// Communicate the result (failure detected or not) back to the caller.
	failureChan <- failureDetected
}
