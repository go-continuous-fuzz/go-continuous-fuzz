package git

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/go-continuous-fuzz/go-continuous-fuzz/config"
	"golang.org/x/sync/errgroup"

	"github.com/go-git/go-git/v5"
)

// sanitizeURL parses the given raw URL string and returns a sanitized version
// in which any user credentials (e.g., a GitHub Personal Access Token) are
// replaced with a placeholder ("*****"). This ensures that sensitive
// information is not exposed in logs or output. If the URL cannot be parsed,
// the original URL is returned.
func sanitizeURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		// If URL parsing fails, return the original URL.
		return rawURL
	}

	// Remove user info (username and password) if present.
	if parsed.User != nil {
		parsed.User = url.User("*****")
	}

	return parsed.String()
}

// Cloner defines the behavior for cloning a repository.
type Cloner interface {
	// Clone performs the cloning operation for a repository.
	Clone(ctx context.Context, logger *slog.Logger) error
}

// RepositoryManager manages multiple repository cloners.
type RepositoryManager struct {
	cloners []Cloner
}

// NewRepositoryManager creates a new instance of RepositoryManager.
func NewRepositoryManager() *RepositoryManager {
	return &RepositoryManager{}
}

// AddCloners adds one or more cloners to the RepositoryManager.
func (rm *RepositoryManager) AddCloners(cloners ...Cloner) {
	rm.cloners = append(rm.cloners, cloners...)
}

// BaseCloner provides common fields and methods for repository cloning.
type BaseCloner struct {
	// URL of the repository to clone.
	URL string

	// Local path where the repository will be cloned.
	Path string

	// Description of the repository.
	Desc string
}

// Clone clones the repository into the specified path.
func (bc *BaseCloner) Clone(ctx context.Context, logger *slog.Logger) error {
	logger.Info("Cloning repository", "url", sanitizeURL(bc.URL),
		"path", bc.Path, "desc", bc.Desc)

	_, err := git.PlainCloneContext(ctx, bc.Path, false, &git.CloneOptions{
		URL: bc.URL,
	})
	if err != nil {
		return fmt.Errorf("%s repository clone failed: %w", bc.Desc,
			err)
	}

	return nil
}

// ProjectCloner is responsible for cloning the project repository.
type ProjectCloner struct {
	*BaseCloner
	// Additional fields related to the project can be added.
}

// StorageCloner is responsible for cloning the storage repository.
type StorageCloner struct {
	*BaseCloner
	// Additional fields related to the storage can be added.
}

// CloneRepositories concurrently clones the project and storage repositories
// based on the provided configuration. It logs progress and returns an error if
// any cloning step fails.
func CloneRepositories(ctx context.Context, logger *slog.Logger,
	cfg *config.Config) error {

	// Prepare a cloner for the project source repository
	projectCloner := &ProjectCloner{
		BaseCloner: &BaseCloner{
			URL:  cfg.ProjectSrcPath,
			Path: config.DefaultProjectDir,
			Desc: "project",
		},
	}

	// Prepare a cloner for the storage corpus repository
	storageCloner := &StorageCloner{
		BaseCloner: &BaseCloner{
			URL:  cfg.GitStorageRepo,
			Path: config.DefaultCorpusDir,
			Desc: "storage",
		},
	}

	// Register both cloners with the repository manager
	repoManager := NewRepositoryManager()
	repoManager.AddCloners(projectCloner, storageCloner)

	// Clone both repos concurrently, with shared context
	g, ctx := errgroup.WithContext(ctx)

	for _, cloner := range repoManager.cloners {
		cloner := cloner
		g.Go(func() error {
			return cloner.Clone(ctx, logger)
		})
	}

	// Wait for both clones to finish or the first error to occur
	if err := g.Wait(); err != nil {
		return fmt.Errorf("error cloning repository: %w", err)
	}

	return nil
}
