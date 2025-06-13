package fuzz

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
	"github.com/go-continuous-fuzz/go-continuous-fuzz/parser"
)

// ListFuzzTargets discovers and returns a list of fuzz targets for the given
// package. It uses "go test -list=^Fuzz" to list the functions and filters
// those that start with "Fuzz".
func ListFuzzTargets(ctx context.Context, logger *slog.Logger,
	cfg *config.Config, pkg string) ([]string, error) {

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

// ExecuteFuzzTarget runs the specified fuzz target for a package for a given
// duration using the "go test" command. It sets up the necessary environment,
// starts the command, streams its output, and logs any failures to a log file.
func ExecuteFuzzTarget(ctx context.Context, logger *slog.Logger, pkg string,
	target string, cfg *config.Config, fuzzTime time.Duration) error {

	logger.Info("Executing fuzz target", "package", pkg, "target", target,
		"duration", fuzzTime)

	// Construct the absolute path to the package directory within the
	// temporary project directory.
	pkgPath := filepath.Join(cfg.Project.SrcDir, pkg)

	// Define the path to store the corpus data generated during fuzzing.
	corpusPath := filepath.Join(cfg.Project.CorpusPath, pkg, "testdata",
		"fuzz")

	// Define the path where failing corpus inputs might be saved by the
	// fuzzing process.
	maybeFailingCorpusPath := filepath.Join(pkgPath, "testdata", "fuzz")

	// Prepare the arguments for the 'go test' command to run the specific
	// fuzz target.
	args := []string{
		"test",
		fmt.Sprintf("-fuzz=^%s$", target),
		fmt.Sprintf("-test.fuzzcachedir=%s", corpusPath),
		fmt.Sprintf("-fuzztime=%s", fuzzTime),
		fmt.Sprintf("-parallel=1"),
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

	// Stream and process the standard output of 'go test', which may
	// include both stdout and stderr content.
	processor := parser.NewFuzzOutputProcessor(logger.
		With("target", target).With("package", pkg), cfg,
		maybeFailingCorpusPath, target)
	isFailing := processor.ProcessFuzzStream(stdout)

	// Wait for the 'go test' command to finish execution.
	err = cmd.Wait()

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

	return nil
}
