package lbd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
)

// Verify S3LogStore implements LogStore at compile time.
var _ LogStore = (*S3LogStore)(nil)

// S3UploaderConfig holds configuration for S3-based log uploads.
type S3UploaderConfig struct {
	Bucket   string
	Prefix   string
	Endpoint string
	Region   string
}

// S3Uploader uploads log files to an S3-compatible endpoint.
type S3Uploader struct {
	client *s3.Client
	cfg    S3UploaderConfig
}

// NewS3Uploader creates an S3Uploader from the given configuration.
// It loads default AWS credentials and applies any custom endpoint/region.
func NewS3Uploader(ctx context.Context, cfg S3UploaderConfig) (*S3Uploader, error) {
	var opts []func(*config.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, config.WithRegion(cfg.Region))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	var s3Opts []func(*s3.Options)
	if cfg.Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = &cfg.Endpoint
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, s3Opts...)
	return &S3Uploader{client: client, cfg: cfg}, nil
}

// Upload sends a local log file to S3 with the key layout:
// <prefix>/<volName>/disk.<label>.log
func (u *S3Uploader) Upload(ctx context.Context, volName, label, localPath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	key := path.Join(u.cfg.Prefix, volName, "disk."+label+".log")
	contentType := "application/octet-stream"

	_, err = u.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &u.cfg.Bucket,
		Key:         &key,
		Body:        f,
		ContentType: &contentType,
	})
	if err != nil {
		return fmt.Errorf("uploading to s3://%s/%s: %w", u.cfg.Bucket, key, err)
	}

	return nil
}

// ListLogs returns the S3 keys of all .log files under <prefix>/<volName>/,
// sorted lexicographically. Keys ending in .log.tmp are excluded.
func (u *S3Uploader) ListLogs(ctx context.Context, volName string) ([]string, error) {
	prefix := path.Join(u.cfg.Prefix, volName) + "/"

	paginator := s3.NewListObjectsV2Paginator(u.client, &s3.ListObjectsV2Input{
		Bucket: &u.cfg.Bucket,
		Prefix: &prefix,
	})

	var keys []string
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing s3://%s/%s: %w", u.cfg.Bucket, prefix, err)
		}
		for _, obj := range page.Contents {
			k := *obj.Key
			if strings.HasSuffix(k, ".log") && !strings.HasSuffix(k, ".log.tmp") {
				keys = append(keys, k)
			}
		}
	}

	sort.Strings(keys)
	return keys, nil
}

// OpenLog retrieves an object from S3 and returns its body as an io.ReadCloser.
// The caller is responsible for closing the returned reader.
func (u *S3Uploader) OpenLog(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := u.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &u.cfg.Bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, fmt.Errorf("getting s3://%s/%s: %w", u.cfg.Bucket, key, err)
	}
	return out.Body, nil
}

// DeleteLog removes an object from S3.
func (u *S3Uploader) DeleteLog(ctx context.Context, key string) error {
	_, err := u.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &u.cfg.Bucket,
		Key:    &key,
	})
	if err != nil {
		return fmt.Errorf("deleting s3://%s/%s: %w", u.cfg.Bucket, key, err)
	}
	return nil
}

// S3LogStore implements LogStore using an S3Uploader for a specific volume.
type S3LogStore struct {
	uploader *S3Uploader
	volName  string
}

// NewS3LogStore creates a LogStore backed by S3 for the given volume.
func NewS3LogStore(uploader *S3Uploader, volName string) *S3LogStore {
	return &S3LogStore{uploader: uploader, volName: volName}
}

func (s *S3LogStore) List(ctx context.Context) ([]string, error) {
	return s.uploader.ListLogs(ctx, s.volName)
}

func (s *S3LogStore) Open(ctx context.Context, id string) (io.ReadCloser, error) {
	return s.uploader.OpenLog(ctx, id)
}

func (s *S3LogStore) Put(ctx context.Context, id string, localPath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	contentType := "application/octet-stream"
	_, err = s.uploader.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &s.uploader.cfg.Bucket,
		Key:         &id,
		Body:        f,
		ContentType: &contentType,
	})
	if err != nil {
		return fmt.Errorf("uploading to s3://%s/%s: %w", s.uploader.cfg.Bucket, id, err)
	}
	return nil
}

func (s *S3LogStore) Delete(ctx context.Context, id string) error {
	return s.uploader.DeleteLog(ctx, id)
}

func (s *S3LogStore) LogPath(label string) string {
	return path.Join(s.uploader.cfg.Prefix, s.volName, "disk."+label+".log")
}

func (s *S3LogStore) OpenLiveMap(ctx context.Context) (io.ReadCloser, error) {
	key := path.Join(s.uploader.cfg.Prefix, s.volName, "livemap.cbor")
	out, err := s.uploader.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &s.uploader.cfg.Bucket,
		Key:    &key,
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) && ae.ErrorCode() == "NoSuchKey" {
			return nil, nil
		}
		return nil, fmt.Errorf("getting live map from s3://%s/%s: %w", s.uploader.cfg.Bucket, key, err)
	}
	return out.Body, nil
}

func (s *S3LogStore) PutLiveMap(ctx context.Context, localPath string) error {
	key := path.Join(s.uploader.cfg.Prefix, s.volName, "livemap.cbor")
	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	contentType := "application/cbor"
	_, err = s.uploader.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      &s.uploader.cfg.Bucket,
		Key:         &key,
		Body:        f,
		ContentType: &contentType,
	})
	if err != nil {
		return fmt.Errorf("uploading live map to s3://%s/%s: %w", s.uploader.cfg.Bucket, key, err)
	}
	return nil
}
