package lbd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setTestAWSCreds(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
}

func TestS3Uploader_Upload(t *testing.T) {
	setTestAWSCreds(t)

	// Create a temp file to upload
	dir := t.TempDir()
	logFile := filepath.Join(dir, "disk.abc123.log")
	content := "test log data here"
	require.NoError(t, os.WriteFile(logFile, []byte(content), 0644))

	var capturedKey string
	var capturedBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedKey = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := NewS3Uploader(context.Background(), S3UploaderConfig{
		Bucket:   "test-bucket",
		Prefix:   "backups",
		Endpoint: srv.URL,
		Region:   "us-east-1",
	})
	require.NoError(t, err)

	err = u.Upload(context.Background(), "vol0", "abc123", logFile)
	require.NoError(t, err)

	assert.True(t, strings.Contains(capturedKey, "backups/vol0/disk.abc123.log"),
		"expected key path in %s", capturedKey)
	assert.Equal(t, content, capturedBody)
}

func TestS3Uploader_ServerError(t *testing.T) {
	setTestAWSCreds(t)

	dir := t.TempDir()
	logFile := filepath.Join(dir, "disk.err.log")
	require.NoError(t, os.WriteFile(logFile, []byte("data"), 0644))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<?xml version="1.0"?><Error><Code>InternalError</Code><Message>fail</Message></Error>`))
	}))
	defer srv.Close()

	u, err := NewS3Uploader(context.Background(), S3UploaderConfig{
		Bucket:   "test-bucket",
		Prefix:   "backups",
		Endpoint: srv.URL,
		Region:   "us-east-1",
	})
	require.NoError(t, err)

	err = u.Upload(context.Background(), "vol0", "err", logFile)
	assert.Error(t, err)
}

func TestS3Uploader_MissingFile(t *testing.T) {
	setTestAWSCreds(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be called for missing file")
	}))
	defer srv.Close()

	u, err := NewS3Uploader(context.Background(), S3UploaderConfig{
		Bucket:   "test-bucket",
		Prefix:   "backups",
		Endpoint: srv.URL,
		Region:   "us-east-1",
	})
	require.NoError(t, err)

	err = u.Upload(context.Background(), "vol0", "missing", "/nonexistent/file.log")
	assert.Error(t, err)
}

func TestS3Uploader_ListLogs(t *testing.T) {
	setTestAWSCreds(t)

	listResp := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-bucket</Name>
  <Prefix>backups/vol0/</Prefix>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>backups/vol0/disk.0002.log</Key>
    <Size>100</Size>
  </Contents>
  <Contents>
    <Key>backups/vol0/disk.0001.log</Key>
    <Size>200</Size>
  </Contents>
  <Contents>
    <Key>backups/vol0/disk.0003.log.tmp</Key>
    <Size>50</Size>
  </Contents>
</ListBucketResult>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(listResp))
	}))
	defer srv.Close()

	u, err := NewS3Uploader(context.Background(), S3UploaderConfig{
		Bucket:   "test-bucket",
		Prefix:   "backups",
		Endpoint: srv.URL,
		Region:   "us-east-1",
	})
	require.NoError(t, err)

	keys, err := u.ListLogs(context.Background(), "vol0")
	require.NoError(t, err)

	// Should be sorted and exclude .log.tmp
	assert.Equal(t, []string{
		"backups/vol0/disk.0001.log",
		"backups/vol0/disk.0002.log",
	}, keys)
}

func TestS3Uploader_OpenLog(t *testing.T) {
	setTestAWSCreds(t)

	body := "fake log body content"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	u, err := NewS3Uploader(context.Background(), S3UploaderConfig{
		Bucket:   "test-bucket",
		Prefix:   "backups",
		Endpoint: srv.URL,
		Region:   "us-east-1",
	})
	require.NoError(t, err)

	rc, err := u.OpenLog(context.Background(), "backups/vol0/disk.0001.log")
	require.NoError(t, err)
	defer rc.Close()

	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, body, string(got))
}
