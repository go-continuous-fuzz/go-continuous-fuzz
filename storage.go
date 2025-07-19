package main

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3Store encapsulates the configuration and state needed to manage S3‑backed
// operations, including context, logger, S3 client configuration, local
// corpus/reports directory and ZIP file handling.
type S3Store struct {
	ctx       context.Context
	client    *s3.Client
	logger    *slog.Logger
	bucket    string
	zipKey    string
	corpusDir string
	reportDir string
	zipPath   string
}

// NewS3Store constructs a S3Store for the given context, logger, and config.
func NewS3Store(ctx context.Context, logger *slog.Logger,
	cfg *Config) (*S3Store, error) {

	s3cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return &S3Store{
		ctx:       ctx,
		client:    s3.NewFromConfig(s3cfg),
		logger:    logger,
		bucket:    cfg.Project.S3BucketName,
		zipKey:    cfg.Project.CorpusKey,
		corpusDir: cfg.Project.CorpusDir,
		reportDir: cfg.Project.ReportDir,
		zipPath:   fmt.Sprintf("%s.zip", cfg.Project.CorpusDir),
	}, nil
}

// downloadObject attempts to download an object from the specified S3 bucket
// and key and saves it to the given destination path on the local filesystem.
//
// If the object does not exist (NoSuchKey), it logs the event and returns true
// with a nil error, indicating that the process should continue with an empty
// data. For all other errors, it returns false and the corresponding error.
func (s3s *S3Store) downloadObject(outPath, key string) (bool, error) {
	// Create destination file
	outFile, err := os.Create(outPath)
	if err != nil {
		return false, fmt.Errorf("creating local file: %w", err)
	}
	defer func() {
		if err := outFile.Close(); err != nil {
			s3s.logger.Error("Failed to close file", "error", err)
		}
	}()

	downloader := manager.NewDownloader(s3s.client)
	n, err := downloader.Download(s3s.ctx, outFile, &s3.GetObjectInput{
		Bucket: &s3s.bucket,
		Key:    &key,
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return true, nil
		}
		return false, fmt.Errorf("downloading s3://%s/%s: %w",
			s3s.bucket, key, err)
	}

	s3s.logger.Info("Downloaded object", "bytes", n, "s3Bucket", s3s.bucket,
		"key", key, "destPath", outPath)

	return false, nil
}

// uploadObject uploads the content read from fileReader to the S3Store's bucket
// at the specified key, setting the Content-Type header to contentType.
func (s3s *S3Store) uploadObject(fileReader io.Reader, key,
	contentType string) error {

	uploader := manager.NewUploader(s3s.client)
	_, err := uploader.Upload(s3s.ctx, &s3.PutObjectInput{
		Bucket:      &s3s.bucket,
		Key:         &key,
		Body:        fileReader,
		ContentType: &contentType,
	})
	if err != nil {
		return fmt.Errorf("uploading s3://%s/%s: %w", s3s.bucket, key,
			err)
	}

	s3s.logger.Info("Uploaded object to S3", "s3Bucket", s3s.bucket, "key",
		key)

	return nil
}

// unzip extracts the contents of the zip archive specified by zipPath into the
// destination directory corpusDir.
//
// It preserves file permissions and directory structure.
func (s3s *S3Store) unzip() error {
	r, err := zip.OpenReader(s3s.zipPath)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			s3s.logger.Error("Failed to close file", "error", err)
		}
	}()

	for _, f := range r.File {
		if err := func(f *zip.File) error {
			fullPath := filepath.Join(filepath.Dir(s3s.corpusDir),
				f.Name)

			if f.FileInfo().IsDir() {
				err := os.MkdirAll(fullPath, f.Mode())
				if err != nil {
					return fmt.Errorf("creating dir %q: %w",
						fullPath, err)
				}
				return nil
			}

			if err := os.MkdirAll(filepath.Dir(fullPath),
				0755); err != nil {
				return fmt.Errorf("creating parent dir for "+
					"%q: %w", fullPath, err)
			}

			srcFile, err := f.Open()
			if err != nil {
				return fmt.Errorf("opening zip file %q: %w",
					f.Name, err)
			}
			defer func() {
				if err := srcFile.Close(); err != nil {
					s3s.logger.Error("Failed to close "+
						"file", "error", err)
				}
			}()

			destFile, err := os.OpenFile(fullPath,
				os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
			if err != nil {
				return fmt.Errorf("creating file %q: %w",
					fullPath, err)
			}
			defer func() {
				if err := destFile.Close(); err != nil {
					s3s.logger.Error("Failed to close "+
						"file", "error", err)
				}
			}()

			if _, err := io.Copy(destFile, srcFile); err != nil {
				return fmt.Errorf("copying to file %q: %w",
					fullPath, err)
			}
			return nil
		}(f); err != nil {
			return err
		}
	}

	return nil
}

// zipDir compresses the contents of the corpusDir into a ZIP archive and writes
// the archive to the provided io.PipeWriter.
//
// It is typically run in a separate goroutine and paired with an io.PipeReader
// for streaming uploads (to AWS S3).
func (s3s *S3Store) zipDir(zipWriter *io.PipeWriter) error {
	zw := zip.NewWriter(zipWriter)
	defer func() {
		if err := zw.Close(); err != nil {
			s3s.logger.Error("Failed to close zip writer", "error",
				err)
		}
	}()

	baseDir := filepath.Clean(s3s.corpusDir)

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo,
		walkErr error) error {

		if walkErr != nil {
			return walkErr
		}

		relPath, err := filepath.Rel(filepath.Dir(baseDir), path)
		if err != nil {
			return err
		}

		relPath = filepath.ToSlash(relPath)

		if info.IsDir() {
			header := &zip.FileHeader{
				Name:   relPath + "/",
				Method: zip.Deflate,
			}
			header.SetMode(info.Mode())
			_, err := zw.CreateHeader(header)
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("opening file %q: %w", path, err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				s3s.logger.Error("Failed to close file",
					"error", err)
			}
		}()

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = relPath
		header.Method = zip.Deflate
		header.SetMode(info.Mode())

		writer, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}

		_, err = io.Copy(writer, file)
		return err
	})

	if err != nil {
		return err
	}

	return nil
}

// uploadCorpusAndReports streams corpusDir as a ZIP archive, uploads it to S3,
// and then uploads any generated coverage reports.
func (s3s *S3Store) uploadCorpusAndReports() error {
	// Stream the ZIP archive in a goroutine.
	pr, pw := io.Pipe()
	go func() {
		err := s3s.zipDir(pw)
		if err != nil {
			s3s.logger.Error("Failed to stream zip", "error", err)
		}
		pw.CloseWithError(err)
	}()

	if err := s3s.uploadObject(pr, s3s.zipKey, "application/zip"); err !=
		nil {

		return fmt.Errorf("corpus upload failed: %w", err)
	}

	s3s.logger.Info("Successfully zipped and uploaded corpus", "s3Bucket",
		s3s.bucket, "key", s3s.zipKey)

	if err := s3s.uploadReports(); err != nil {
		return fmt.Errorf("reports upload failed: %w", err)
	}

	s3s.logger.Info("Successfully uploaded reports", "s3Bucket", s3s.bucket)

	return nil
}

// downloadCorpusAndReports downloads the ZIP archive from S3 and unzips it into
// the local corpusDir (unless the archive is empty), and then downloads any
// associated reports.
func (s3s *S3Store) downloadCorpusAndReports() error {
	empty, err := s3s.downloadObject(s3s.zipPath, s3s.zipKey)
	if err != nil {
		return fmt.Errorf("corpus download failed: %w", err)
	}

	if empty {
		s3s.logger.Info("Corpus object not found. Starting with empty "+
			"corpus.", "s3Bucket", s3s.bucket, "key", s3s.zipKey)

		return nil
	}

	if err := s3s.unzip(); err != nil {
		return fmt.Errorf("corpus unzip failed: %w", err)
	}

	s3s.logger.Info("Successfully downloaded and unzipped corpus",
		"s3Bucket", s3s.bucket, "key", s3s.zipKey)

	if err := s3s.downloadReports(); err != nil {
		return fmt.Errorf("reports download failed: %w", err)
	}

	s3s.logger.Info("Successfully downloaded reports", "s3Bucket",
		s3s.bucket)

	return nil
}

// downloadReports downloads all JSON report files from the configured S3 bucket
// saving each under reports directory.
func (s3s *S3Store) downloadReports() error {
	// Initialize a paginator for listing all objects in the bucket
	paginator := s3.NewListObjectsV2Paginator(s3s.client,
		&s3.ListObjectsV2Input{Bucket: &s3s.bucket})

	// Iterate through each page of results
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(s3s.ctx)
		if err != nil {
			return fmt.Errorf("failed to list objects: %w", err)
		}

		// Process each object in the current page
		for _, item := range page.Contents {
			key := *item.Key

			// Skip any file that does not have a .json extension
			if filepath.Ext(key) != ".json" {
				continue
			}

			localPath := filepath.Join(s3s.reportDir, key)
			err := EnsureDirExists(filepath.Dir(localPath))
			if err != nil {
				return fmt.Errorf("creating report directory: "+
					"%w", err)
			}

			// Download the JSON report object to the local path
			_, err = s3s.downloadObject(localPath, key)
			if err != nil {
				return fmt.Errorf("download report %q: %w", key,
					err)
			}
		}
	}
	return nil
}

// uploadReports walks the local reportDir, uploading each file to S3.
// It preserves the directory structure by using each file's path relative to
// reportDir as the S3 key.
func (s3s *S3Store) uploadReports() error {
	return filepath.Walk(s3s.reportDir, func(path string, info os.FileInfo,
		err error) error {

		if err != nil || info.IsDir() {
			return err
		}

		// Compute the key by making the path relative to reportDir
		relPath, err := filepath.Rel(s3s.reportDir, path)
		if err != nil {
			return fmt.Errorf("determine relative path: %w", err)
		}
		key := filepath.ToSlash(relPath)

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open report %q: %w", path, err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				s3s.logger.Error("Failed to close file",
					"error", err)
			}
		}()

		// Upload the file to S3 with the appropriate content type
		contentType := detectContentType(path)
		if err = s3s.uploadObject(file, key, contentType); err != nil {
			return fmt.Errorf("upload report %q: %w", key, err)
		}

		return nil
	})
}

// detectContentType returns the MIME type for filename based on its extension.
// If the extension is unknown, it defaults to application/octet-stream.
func detectContentType(filename string) string {
	ext := filepath.Ext(filename)
	if mimeType := mime.TypeByExtension(ext); mimeType != "" {
		return mimeType
	}
	// Fallback to a generic binary stream
	return "application/octet-stream"
}
