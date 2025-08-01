package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

// MeasureCoverage runs a Go fuzz target using the inputs from its corpus
// directory and returns the best observed coverage (in coverage bits).
//
// It does this by:
//  1. Reading the corpus files for the given target.
//  2. Running `go test` with one fuzz iteration per file.
//  3. Extracting the coverage bits from the command output.
func MeasureCoverage(ctx context.Context, pkgDir, corpusDir,
	target string) (int, error) {

	// Gather existing corpus files to size the fuzz run
	corpusTargetDir := filepath.Join(corpusDir, target)
	files, err := os.ReadDir(corpusTargetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("reading corpus dir: %w", err)
	}

	// Build and run the fuzz command.
	// Command arguments (explanations):
	//
	//   -run=^%s$ -fuzz=^%s$
	// When the -fuzz flag is provided, `go test` normally runs all unit
	// tests before doing any fuzzing. Passing -run together with -fuzz
	// skips the initial unit-test run so we only exercise the fuzz target.
	//
	//   -fuzztime=%dx
	// Set fuzztime to exactly the number of inputs in the corpus directory
	// so the Go fuzzing engine stops after measuring baseline coverage and
	// does not perform any actual fuzzing iterations.
	//
	//   -test.fuzzcachedir=%s
	// Use a dedicated fuzz cache directory to avoid cross-contamination
	// with the default cache.
	fuzzCmd := []string{"test",
		fmt.Sprintf("-run=^%s$", target),
		fmt.Sprintf("-fuzz=^%s$", target),
		fmt.Sprintf("-fuzztime=%dx", len(files)),
		fmt.Sprintf("-test.fuzzcachedir=%s", corpusDir),
	}

	// Run the go test command with GODEBUG to enable fuzzdebug output.
	//
	// When GODEBUG=fuzzdebug=1 is set, the Go fuzzing engine prints extra
	// diagnostic information. We look for the line printed after all inputs
	// in the fuzz cache have been processed, for example:
	//   DEBUG finished processing ... initial coverage bits: XXX
	output, err := runGoCommand(ctx, pkgDir, fuzzCmd, "GODEBUG=fuzzdebug=1")
	if err != nil {
		return 0, fmt.Errorf("go test failed for %q: %w ", pkgDir, err)
	}

	// Parse the fuzz output to extract the initial coverage bits.
	//
	// Return the number of coverage bits printed by the Go fuzzing engine
	// after it finishes processing all inputs in the fuzz cache.
	coverageRe := regexp.MustCompile(`initial coverage bits:\s+([0-9]+)\n`)
	matches := coverageRe.FindStringSubmatch(output)
	if len(matches) < 2 {
		return 0, fmt.Errorf("coverage bits not found in output:\n%s",
			output)
	}

	coverage, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, fmt.Errorf("parsing coverage: %w", err)
	}

	return coverage, nil
}

// MinimizeCorpus prunes unnecessary seed inputs from the corpus directory
// while preserving the maximum observed coverage. It works by iteratively
// testing each seed input (from smallest to largest, greedily) and removing
// those that do not contribute to improved coverage.
func MinimizeCorpus(ctx context.Context, logger *slog.Logger, pkgDir, corpusDir,
	target string) error {

	// Remove the seed fuzz testdata directory to start fresh.
	fuzzTestDataDir := filepath.Join(pkgDir, "testdata", "fuzz", target)
	if err := os.RemoveAll(fuzzTestDataDir); err != nil {
		return fmt.Errorf("removing testdata: %w", err)
	}

	// Temporary directory for the corpus cache where inputs will be added
	// one by one to check if they increase coverage.
	cacheDir, err := os.MkdirTemp("", "go-continuous-fuzz-cache-")
	if err != nil {
		return fmt.Errorf("creating temp cache dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(cacheDir); err != nil {
			logger.Error("Failed to remove cache", "error", err)
		}
	}()

	cacheCorpusDir := filepath.Join(cacheDir, target)
	if err := EnsureDirExists(cacheCorpusDir); err != nil {
		return fmt.Errorf("creating cache corpus dir: %w", err)
	}

	// Read and sort existing corpus files by size, so we iterate from the
	// smallest to largest input, greedily adding those that improve
	// coverage.
	corpusTargetDir := filepath.Join(corpusDir, target)
	entries, err := os.ReadDir(corpusTargetDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading corpus dir: %w", err)
	}

	// fileInfo represents the name and size of a file, used for sorting
	// files by their size.
	type fileInfo struct {
		Name string
		Size int64
	}

	// Collect file information for sorting by size.
	var files []fileInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("getting file info for %s: %w",
				entry.Name(), err)
		}
		files = append(files, fileInfo{
			Name: entry.Name(),
			Size: info.Size(),
		})
	}

	// Sort files from smallest to largest by size.
	sort.Slice(files, func(i, j int) bool {
		return files[i].Size < files[j].Size
	})

	bestCoverage := 0
	removedCount := 0

	// Iterate through each corpus file, measure its impact on coverage,
	// and remove it if it does not improve or reduces the coverage.
	for _, file := range files {
		srcPath := filepath.Join(corpusTargetDir, file.Name)
		dstPath := filepath.Join(cacheCorpusDir, file.Name)

		// Copy file to temporary corpus directory.
		if err := copyFile(srcPath, dstPath, logger); err != nil {
			return fmt.Errorf("copy %q to cache: %w", srcPath, err)
		}

		// Measure coverage with the current set in the temporary corpus
		// directory.
		newCoverage, err := MeasureCoverage(ctx, pkgDir, cacheDir,
			target)
		if err != nil {
			return fmt.Errorf("measuring base coverage: %w", err)
		}

		if newCoverage > bestCoverage {
			bestCoverage = newCoverage
			continue
		}

		if newCoverage < bestCoverage {
			logger.Warn("nondeterministic fuzz target: coverage "+
				"decreased", "file", file.Name, "oldCoverage",
				bestCoverage, "newCoverage", newCoverage)
		}

		// Remove the file from both the source and cache directories
		// since it did not improve coverage or caused a coverage
		// regression.
		if err := os.Remove(srcPath); err != nil {
			return fmt.Errorf("remove %q: %w", srcPath, err)
		}
		if err := os.Remove(dstPath); err != nil {
			return fmt.Errorf("remove %q: %w", dstPath, err)
		}
		removedCount++
	}

	logger.Info("corpus minimization complete", "removedCount",
		removedCount, "finalCoverage", bestCoverage)
	return nil
}
