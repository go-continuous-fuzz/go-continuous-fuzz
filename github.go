package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/client"
	"github.com/google/go-github/v72/github"
	"golang.org/x/oauth2"
)

// GitHubRepo encapsulates the context, configuration, clients, and logger
// for operating on a specific GitHub repository.
type GitHubRepo struct {
	ctx    context.Context
	logger *slog.Logger
	client *github.Client
	cli    *client.Client
	cfg    *Config
	owner  string
	repo   string
}

// NewGitHubRepo constructs a GitHubRepo instance by parsing the repository URL.
// It extracts the owner, repository name, and token for authentication.
func NewGitHubRepo(ctx context.Context, logger *slog.Logger, cli *client.Client,
	cfg *Config) (*GitHubRepo, error) {

	u, err := url.Parse(cfg.Fuzz.CrashRepo)
	if err != nil {
		return nil, fmt.Errorf("invalid repository URL: %w", err)
	}

	owner, repo, err := extractOwnerRepo(u)
	if err != nil {
		return nil, err
	}

	token := extractToken(u)
	if token == "" {
		return nil, fmt.Errorf("authentication token not provided in "+
			"repository URL: %s", cfg.Fuzz.CrashRepo)
	}

	return &GitHubRepo{
		ctx:    ctx,
		logger: logger,
		client: createGitHubClient(ctx, token),
		cli:    cli,
		cfg:    cfg,
		owner:  owner,
		repo:   repo,
	}, nil
}

// extractToken retrieves the access token from the repository URL, if provided.
func extractToken(u *url.URL) string {
	if u.User != nil {
		if pwd, ok := u.User.Password(); ok {
			return pwd
		}
	}
	return ""
}

// extractOwnerRepo parses the owner and repository name from the URL path.
func extractOwnerRepo(u *url.URL) (string, string, error) {
	parts := strings.Split(strings.TrimSuffix(u.Path, ".git"), "/")
	if len(parts) < 3 {
		return "", "", fmt.Errorf("invalid repository path")
	}
	return parts[1], parts[2], nil
}

// createGitHubClient initializes the GitHub client, using a provided token for
// authentication.
func createGitHubClient(ctx context.Context, token string) *github.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: token,
	})
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

// listOpenIssues retrieves all open GitHub issues in the repository that match
// the exact title.
func (gh *GitHubRepo) listOpenIssues(title string) ([]*github.Issue, error) {
	gh.logger.Info("Listing GitHub issues", "owner", gh.owner, "repo",
		gh.repo, "title", title)

	// Build a search query that restricts to this repo and the exact title
	// Perform the search
	query := fmt.Sprintf(`repo:%s/%s is:issue is:open "%s"`, gh.owner,
		gh.repo, title)
	results, _, err := gh.client.Search.Issues(gh.ctx, query,
		&github.SearchOptions{})
	if err != nil {
		gh.logger.Error("Failed to list GitHub issues", "query", query,
			"err", err)
		return []*github.Issue{}, err
	}

	return results.Issues, nil
}

// issueExists checks whether an issue with the exact title already exists.
func (gh *GitHubRepo) issueExists(title string) (bool, error) {
	gh.logger.Info("Searching for existing issue", "owner", gh.owner,
		"repo", gh.repo, "title", title)

	issues, err := gh.listOpenIssues(title)
	if err != nil {
		gh.logger.Error("GitHub issue search failed", "err", err)
		return false, err
	}

	if len(issues) > 0 {
		gh.logger.Info("Issue already exists", "url",
			issues[0].GetHTMLURL())
		return true, nil
	}

	return false, nil
}

// createIssue opens a new GitHub issue with the given title and body.
func (gh *GitHubRepo) createIssue(title, body string) error {
	gh.logger.Info("Creating new issue", "owner", gh.owner, "repo", gh.repo,
		"title", title)

	req := &github.IssueRequest{Title: &title, Body: &body}
	issue, _, err := gh.client.Issues.Create(gh.ctx, gh.owner, gh.repo, req)
	if err != nil {
		gh.logger.Error("Issue creation failed", "err", err)
		return err
	}

	gh.logger.Info("Issue created successfully", "url", issue.GetHTMLURL())
	return nil
}

// closeIssue closes an existing GitHub issue by its number.
func (gh *GitHubRepo) closeIssue(number int) error {
	gh.logger.Info("Closing issue", "owner", gh.owner, "repo", gh.repo,
		"issueNumber", number)

	req := &github.IssueRequest{State: github.Ptr("closed")}
	issue, _, err := gh.client.Issues.Edit(gh.ctx, gh.owner, gh.repo,
		number, req)
	if err != nil {
		gh.logger.Error("Issue closure failed", "err", err)
		return err
	}

	gh.logger.Info("Issue closed successfully", "url", issue.GetHTMLURL())
	return nil
}

// handleCrash posts a GitHub issue for a new fuzz crash if one does not exist.
// It computes a unique crash signature, formats a report, and avoids duplicates
// by checking for an existing issue with the same title.
func (gh *GitHubRepo) handleCrash(pkg, target string, fc fuzzCrash) error {
	// Compute a short signature hash for the crash to help with
	// deduplication.
	crashHash := ComputeSHA256Short(fc.failureFileAndLine)

	// Compose issue title and body
	title := fmt.Sprintf("[fuzz/%s] Fuzzing crash in %s/%s", crashHash, pkg,
		target)
	body := formatCrashReport(fc.errorLogs, fc.failingInput)

	// Check for existing issue to prevent duplicates
	exists, err := gh.issueExists(title)
	if err != nil {
		return fmt.Errorf("checking existing GitHub issues: %w", err)
	}

	if exists {
		gh.logger.Info("Fuzz crash already reported", "signature",
			crashHash)
		return nil
	}

	// Create a new issue for this crash
	if err = gh.createIssue(title, body); err != nil {
		return fmt.Errorf("creating GitHub issue: %w", err)
	}

	return nil
}

// verifyAndCloseResolvedIssues checks open issues for a fuzz target, attempts
// to reproduce them, and closes those that are no longer reproducible.
func (gh *GitHubRepo) verifyAndCloseResolvedIssues(pkg, target string) error {
	gh.logger.Info("Verifying open GitHub issues for fuzz target")

	// Listing GitHub issues with the exact same title
	title := fmt.Sprintf("Fuzzing crash in %s/%s", pkg, target)
	issues, err := gh.listOpenIssues(title)
	if err != nil {
		return err
	}

	for _, issue := range issues {
		// Parse the failing input from the issue body
		failingInput, err := parseIssueBody(*issue.Body)
		if err != nil {
			gh.logger.Info("No failing testcase found in body; "+
				"skipping issue, possibly an unrelated issue "+
				"with a similar title", "url",
				issue.GetHTMLURL())
			continue
		}

		// If the crash is due to a seed corpus input added via f.Add,
		// this issue cannot be automatically verified and closed.
		if failingInput == seedCorpusErrMsg {
			gh.logger.Info("Seed corpus crash detected; manual "+
				"verification required", "url",
				issue.GetHTMLURL())
			continue
		}

		// Prepare directory and file for failing input
		fuzzBinaryPath := filepath.Join(gh.cfg.Project.BinaryDir, pkg,
			target)
		failingDir := filepath.Join(fuzzBinaryPath, "testdata", "fuzz",
			target)
		if err := EnsureDirExists(failingDir); err != nil {
			return fmt.Errorf("create testdata directory: %w", err)
		}

		// Write the input to the target's testdata directory
		fileHash := ComputeSHA256Short(failingInput)
		failingFile := filepath.Join(failingDir, fileHash)
		err = os.WriteFile(failingFile, []byte(failingInput), 0644)
		if err != nil {
			return fmt.Errorf("writing failing input to file: %w",
				err)
		}

		// Run the fuzz test for this input and attempt to reproduce the
		// crash.
		testCmd := []string{
			fmt.Sprintf("./%s.test", target),
			fmt.Sprintf("-test.run=%s", filepath.Join(target,
				fileHash)),
		}

		// Attempt to reproduce the crash by running the test inside a
		// container. This allows us to enforce fixed resource limits
		// and prevent interference with other workers, for example, if
		// one worker encounters an out-of-memory error.
		err = gh.reproduceIssue(pkg, target, testCmd, issue)
		if err != nil {
			return fmt.Errorf("reproducing issue %d: %w",
				issue.GetNumber(), err)
		}

		// After verification, remove the failing input file to clean up
		// and avoid leaving any potentially problematic test data.
		if err := os.Remove(failingFile); err != nil {
			return fmt.Errorf("remove %q: %w", failingFile, err)
		}
	}

	return nil
}

// reproduceIssue attempts to reproduce a reported fuzzing issue for a given
// package and target. It runs the fuzz test inside a Docker container using the
// provided test command. If the issue is no longer reproducible, the associated
// GitHub issue will be closed automatically.
func (gh *GitHubRepo) reproduceIssue(pkg, target string, testCmd []string,
	issue *github.Issue) error {

	// Fuzzing container setup for the issue verification.
	c := &Container{
		ctx:    gh.ctx,
		logger: gh.logger,
		cli:    gh.cli,
		fuzzBinaryPath: filepath.Join(gh.cfg.Project.BinaryDir, pkg,
			target),
		hostCorpusPath: filepath.Join(gh.cfg.Project.CorpusDir, pkg,
			"testdata", "fuzz"),
		cmd: testCmd,
	}

	// Start the container for issue verification.
	containerID, err := c.Start()
	if err != nil {
		return fmt.Errorf("failed to start verification container "+
			"for %s/%s: %w", pkg, target, err)
	}
	defer c.Stop(containerID)

	// After running the fuzzing container for this issue, if it crashes
	// again (Wait returns an error), the crash is still reproducible and
	// the GitHub issue is kept open. If the container exits cleanly, the
	// crash is no longer reproducible and the corresponding GitHub issue
	// is closed.
	if err := c.Wait(containerID); err != nil {
		gh.logger.Info("Crash still reproducible; keeping GitHub "+
			"issue open", "url", issue.GetHTMLURL())
	} else {
		gh.logger.Info("Crash no longer reproducible; closing "+
			"associated GitHub issue", "url", issue.GetHTMLURL())

		// Close the issue if the crash is resolved
		if err := gh.closeIssue(issue.GetNumber()); err != nil {
			return fmt.Errorf("closing issue: %w", err)
		}
	}

	return nil
}
