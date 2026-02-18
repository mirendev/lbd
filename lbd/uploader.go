package lbd

import (
	"context"
	"path/filepath"
	"strings"
)

// LogUploader uploads log files to a remote store.
type LogUploader interface {
	Upload(ctx context.Context, volName, label, localPath string) error
}

// NopUploader is a no-op LogUploader that discards all uploads.
type NopUploader struct{}

func (NopUploader) Upload(context.Context, string, string, string) error { return nil }

// LabelFromLogPath extracts the label from a log filename like
// "disk.<label>.log" or a full path ending with that filename.
func LabelFromLogPath(p string) string {
	base := filepath.Base(p)
	base = strings.TrimPrefix(base, "disk.")
	base = strings.TrimSuffix(base, ".log")
	return base
}
