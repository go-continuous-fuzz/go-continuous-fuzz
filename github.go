package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/google/go-github/v72/github"
	"golang.org/x/oauth2"
)

// GitHubRepo encapsulates configuration and GitHub client for operating on a
// specific repository.
type GitHubRepo struct {
	ctx    context.Context
	logger *slog.Logger
	client *github.Client
	owner  string
	repo   string
}

// NewGitHubRepo constructs a GitHubRepo instance by parsing the repository URL.
// It extracts the owner, repository name, and token for authentication.
func NewGitHubRepo(ctx context.Context, logger *slog.Logger, repoURL string,
) (*GitHubRepo, error) {

	u, err := url.Parse(repoURL)
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
			"repository URL: %s", repoURL)
	}

	return &GitHubRepo{
		ctx:    ctx,
		logger: logger,
		client: createGitHubClient(ctx, token),
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

// issueExists checks whether an issue with the exact title already exists.
func (gh *GitHubRepo) issueExists(title string) (bool, error) {
	gh.logger.Info("Searching for existing issue", "owner", gh.owner,
		"repo", gh.repo, "title", title)

	// Build a search query that restricts to this repo and the exact title
	// Perform the search
	query := fmt.Sprintf(`repo:%s/%s is:issue is:open "%s"`, gh.owner,
		gh.repo, title)
	results, _, err := gh.client.Search.Issues(gh.ctx, query,
		&github.SearchOptions{})
	if err != nil {
		gh.logger.Error("GitHub issue search failed", "query", query,
			"err", err)
		return false, err
	}

	if len(results.Issues) > 0 {
		gh.logger.Info("Issue already exists", "url",
			results.Issues[0].GetHTMLURL())
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
