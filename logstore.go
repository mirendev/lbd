package lbd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// LogStore abstracts log segment storage for GC and other operations
// that need to list, read, write, and delete log segments.
type LogStore interface {
	// List returns log segment identifiers sorted lexicographically.
	// For local stores these are full file paths; for S3 stores they are S3 keys.
	List(ctx context.Context) ([]string, error)

	// Open returns a reader for the identified log segment.
	Open(ctx context.Context, id string) (io.ReadCloser, error)

	// Put stores the contents of localPath under the given identifier.
	Put(ctx context.Context, id string, localPath string) error

	// Delete removes the identified log segment.
	Delete(ctx context.Context, id string) error

	// LogPath returns the identifier for a new log with the given label.
	LogPath(label string) string

	// OpenLiveMap opens the live map for reading.
	// Returns nil, nil if the live map does not exist.
	OpenLiveMap(ctx context.Context) (io.ReadCloser, error)

	// PutLiveMap stores the live map from a local file path.
	PutLiveMap(ctx context.Context, localPath string) error
}

// DirLogStore implements LogStore using a local directory.
type DirLogStore struct {
	Dir string
}

func (s *DirLogStore) List(ctx context.Context) ([]string, error) {
	return DiscoverLogFiles(s.Dir)
}

func (s *DirLogStore) Open(ctx context.Context, id string) (io.ReadCloser, error) {
	return os.Open(id)
}

func (s *DirLogStore) Put(ctx context.Context, id string, localPath string) error {
	// Try same-filesystem rename first.
	if err := os.Rename(localPath, id); err == nil {
		return nil
	}

	// Cross-filesystem fallback: copy to tmp in target dir, then rename.
	tmpPath := id + ".tmp"

	in, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("opening source: %w", err)
	}
	defer in.Close()

	out, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("creating temp: %w", err)
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("copying: %w", err)
	}

	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("syncing: %w", err)
	}

	if err := out.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("closing: %w", err)
	}

	return os.Rename(tmpPath, id)
}

func (s *DirLogStore) Delete(ctx context.Context, id string) error {
	return os.Remove(id)
}

func (s *DirLogStore) LogPath(label string) string {
	return filepath.Join(s.Dir, "disk."+label+".log")
}

func (s *DirLogStore) OpenLiveMap(ctx context.Context) (io.ReadCloser, error) {
	f, err := os.Open(filepath.Join(s.Dir, "livemap.cbor"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return f, err
}

func (s *DirLogStore) PutLiveMap(ctx context.Context, localPath string) error {
	return s.Put(ctx, filepath.Join(s.Dir, "livemap.cbor"), localPath)
}
