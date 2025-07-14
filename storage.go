package main

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3CorpusStore encapsulates the configuration and state needed to manage
// S3‑backed corpus operations, including context, logger, S3 client
// configuration, local corpus directory and ZIP file handling (download,
// zip/unzip, upload).
type S3CorpusStore struct {
	ctx       context.Context
	client    *s3.Client
	logger    *slog.Logger
	bucket    string
	key       string
	corpusDir string
	zipPath   string
}

// NewS3CorpusStore constructs a S3CorpusStore for the given context, logger,
// and config.
func NewS3CorpusStore(ctx context.Context, logger *slog.Logger,
	cfg *Config) (*S3CorpusStore, error) {

	s3cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return &S3CorpusStore{
		ctx:       ctx,
		client:    s3.NewFromConfig(s3cfg),
		logger:    logger,
		bucket:    cfg.Project.S3BucketName,
		key:       cfg.Project.CorpusKey,
		corpusDir: cfg.Project.CorpusDir,
		zipPath:   fmt.Sprintf("%s.zip", cfg.Project.CorpusDir),
	}, nil
}

// downloadObject attempts to download an object from the specified S3 bucket
// and key and saves it to the given destination path on the local filesystem.
//
// If the object does not exist (NoSuchKey), it logs the event and returns true
// with a nil error, indicating that the process should continue with an empty
// corpus. For all other errors, it returns false and the corresponding error.
func (s3cs *S3CorpusStore) downloadObject() (bool, error) {
	// Create destination file
	outFile, err := os.Create(s3cs.zipPath)
	if err != nil {
		return false, fmt.Errorf("creating local file: %w", err)
	}
	defer func() {
		if err := outFile.Close(); err != nil {
			s3cs.logger.Error("Failed to close file", "error",
				err)
		}
	}()

	downloader := manager.NewDownloader(s3cs.client)
	n, err := downloader.Download(s3cs.ctx, outFile, &s3.GetObjectInput{
		Bucket: &s3cs.bucket,
		Key:    &s3cs.key,
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			s3cs.logger.Info("Corpus object not found. Starting "+
				"with empty corpus.", "s3Bucket", s3cs.bucket,
				"key", s3cs.key)
			return true, nil
		}
		return false, fmt.Errorf("downloading s3://%s/%s: %w",
			s3cs.bucket, s3cs.key, err)
	}

	s3cs.logger.Info("Downloaded object", "bytes", n, "s3Bucket",
		s3cs.bucket, "key", s3cs.key, "destPath", s3cs.zipPath)

	return false, nil
}

// uploadObject uploads the ZIP archive stream to the configured S3 bucket and
// object key.
//
// It reads the ZIP data from the provided io.PipeReader, which is typically
// streamed from a concurrent zipping process.
//
// The object is stored with the content type "application/zip".
func (s3cs *S3CorpusStore) uploadObject(zipReader *io.PipeReader) error {
	uploader := manager.NewUploader(s3cs.client)
	_, err := uploader.Upload(s3cs.ctx, &s3.PutObjectInput{
		Bucket:      &s3cs.bucket,
		Key:         &s3cs.key,
		Body:        zipReader,
		ContentType: aws.String("application/zip"),
	})
	if err != nil {
		return fmt.Errorf("uploading s3://%s/%s: %w", s3cs.bucket,
			s3cs.key, err)
	}

	s3cs.logger.Info("Uploaded object to S3", "s3Bucket", s3cs.bucket,
		"key", s3cs.key)

	return nil
}

// unzip extracts the contents of the zip archive specified by zipPath into the
// destination directory corpusDir.
//
// It preserves file permissions and directory structure.
func (s3cs *S3CorpusStore) unzip() error {
	r, err := zip.OpenReader(s3cs.zipPath)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			s3cs.logger.Error("Failed to close file", "error",
				err)
		}
	}()

	for _, f := range r.File {
		if err := func(f *zip.File) error {
			fullPath := filepath.Join(filepath.Dir(s3cs.corpusDir),
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
					s3cs.logger.Error("Failed to close "+
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
					s3cs.logger.Error("Failed to close "+
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
func (s3cs *S3CorpusStore) zipDir(zipWriter *io.PipeWriter) error {
	zw := zip.NewWriter(zipWriter)
	defer func() {
		if err := zw.Close(); err != nil {
			s3cs.logger.Error("Failed to close zip writer", "error",
				err)
		}
	}()

	baseDir := filepath.Clean(s3cs.corpusDir)

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
				s3cs.logger.Error("Failed to close file",
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

// zipUploadCorpus streams the contents of corpusDir as a ZIP archive and
// uploads it to the specified S3 bucket and object key.
func (s3cs *S3CorpusStore) zipUploadCorpus() error {
	// Stream the ZIP archive in a goroutine.
	pr, pw := io.Pipe()
	go func() {
		err := s3cs.zipDir(pw)
		if err != nil {
			s3cs.logger.Error("Failed to stream zip", "error", err)
		}
		pw.CloseWithError(err)
	}()

	if err := s3cs.uploadObject(pr); err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}

	s3cs.logger.Info("Successfully zipped and uploaded corpus", "s3Bucket",
		s3cs.bucket, "key", s3cs.key)

	return nil
}

// downloadUnZipCorpus downloads the ZIP archive from S3 and unzips it into
// the local corpusDir (unless the archive is empty).
func (s3cs *S3CorpusStore) downloadUnZipCorpus() error {
	empty, err := s3cs.downloadObject()
	if err != nil {
		return fmt.Errorf("corpus download failed: %w", err)
	}

	if !empty {
		if err := s3cs.unzip(); err != nil {
			return fmt.Errorf("corpus unzip failed: %w", err)
		}
	}

	s3cs.logger.Info("Successfully downloaded and unzipped corpus",
		"s3Bucket", s3cs.bucket, "key", s3cs.key)

	return nil
}
