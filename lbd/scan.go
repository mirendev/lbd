package lbd

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Scan constants.
const (
	ScanBlockSize = 4096
	ScanRunBlocks = 15
	ScanRunSize   = ScanRunBlocks * ScanBlockSize // 61440

	seekData = 3 // SEEK_DATA
	seekHole = 4 // SEEK_HOLE
)

// ScanConfig holds configuration for a device scan.
type ScanConfig struct {
	DBPath     string // path to SQLite hash database
	LogDir     string // directory to write log segment files
	DevicePath string // block device or file to scan
}

// ScanResult holds the outcome of a device scan.
type ScanResult struct {
	TotalRuns  int64
	DeviceSize int64
	WriteCount int
	TrimCount  int
	WriteBytes uint64
	LogPath    string // path to written log file; empty if no changes
}

// holeRange represents a contiguous hole (unallocated) region in a file.
type holeRange struct {
	start, end int64 // [start, end) byte offsets
}

// BuildHoleMap uses SEEK_DATA/SEEK_HOLE to find all hole regions in a file.
// Returns nil if the filesystem doesn't support SEEK_HOLE (block devices, etc.),
// in which case the caller should skip hole processing entirely.
func BuildHoleMap(f *os.File, size int64) []holeRange {
	if size == 0 {
		return nil
	}

	var holes []holeRange
	pos := int64(0)

	for pos < size {
		// Find next data at or after pos
		dataPos, err := f.Seek(pos, seekData)
		if err != nil {
			if errors.Is(err, syscall.ENXIO) {
				// No more data from pos to EOF — rest is hole
				holes = append(holes, holeRange{start: pos, end: size})
				break
			}
			// EINVAL, ESPIPE, etc. — SEEK_DATA not supported
			return nil
		}

		if dataPos > pos {
			// Hole from pos to dataPos
			holes = append(holes, holeRange{start: pos, end: dataPos})
		}

		// Find next hole at or after dataPos (end of this data region)
		holePos, err := f.Seek(dataPos, seekHole)
		if err != nil {
			// Shouldn't fail (EOF is a virtual hole), but handle gracefully
			break
		}

		pos = holePos
	}

	return holes
}

// isRunInHole reports whether the byte range [start, end) falls entirely
// within a hole.
func isRunInHole(holes []holeRange, start, end int64) bool {
	for _, h := range holes {
		if h.start <= start && h.end >= end {
			return true
		}
	}
	return false
}

// TAI64NLabel returns a TAI64N label string for the current time,
// suitable for use as a log segment label.
func TAI64NLabel() string {
	now := time.Now()
	taiSecs := uint64(now.Unix()) + 0x4000000000000000
	return fmt.Sprintf("%016x%08x", taiSecs, now.Nanosecond())
}

// scanResult represents a single change detected during a scan.
type scanResult struct {
	block  uint64 // starting block number
	isTrim bool
	data   []byte // nil for trims
	crc    uint32
	length int64 // may span multiple runs for coalesced trims
}

// dbUpdate represents a hash update to persist in the database.
type dbUpdate struct {
	offset  int64
	hexHash string
}

// ScanDevice scans a device for changes compared to a hash database,
// and writes any changes as a CBOR log segment file. It returns the
// scan results.
func ScanDevice(cfg ScanConfig) (*ScanResult, error) {
	if cfg.DBPath == "" {
		return nil, fmt.Errorf("database path is required")
	}
	if cfg.LogDir == "" {
		return nil, fmt.Errorf("log directory is required")
	}
	if cfg.DevicePath == "" {
		return nil, fmt.Errorf("device path is required")
	}

	// Open device read-only and determine size
	dev, err := os.Open(cfg.DevicePath)
	if err != nil {
		return nil, fmt.Errorf("opening device: %w", err)
	}
	defer dev.Close()

	deviceSize, err := dev.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("seeking to end: %w", err)
	}

	// Build hole map using SEEK_DATA/SEEK_HOLE (nil if unsupported)
	holes := BuildHoleMap(dev, deviceSize)

	// Open/create SQLite DB
	db, err := OpenDB(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// Compute total runs
	totalRuns := deviceSize / ScanRunSize
	if deviceSize%ScanRunSize != 0 {
		totalRuns++
	}

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	selectStmt, err := tx.Prepare("SELECT sha256 FROM run_hashes WHERE run_offset = ?")
	if err != nil {
		return nil, fmt.Errorf("preparing select: %w", err)
	}
	defer selectStmt.Close()

	// Precompute zeros hash for full-size runs
	zerosFullBuf := make([]byte, ScanRunSize)
	zerosFullSha := sha256.Sum256(zerosFullBuf)
	zerosFullHex := hex.EncodeToString(zerosFullSha[:])

	// Helper to get zeros hash for a given length
	zerosHexForLen := func(length int64) string {
		if length == ScanRunSize {
			return zerosFullHex
		}
		buf := make([]byte, length)
		h := sha256.Sum256(buf)
		return hex.EncodeToString(h[:])
	}

	var logEntries []scanResult
	var dbOps []dbUpdate
	buf := make([]byte, ScanRunSize)

	// Inline trim coalescing state
	pendingTrimStart := int64(-1)
	pendingTrimLen := int64(0)

	flushTrim := func() {
		if pendingTrimStart < 0 {
			return
		}
		logEntries = append(logEntries, scanResult{
			block:  uint64(pendingTrimStart) * ScanRunBlocks,
			isTrim: true,
			length: pendingTrimLen,
		})
		pendingTrimStart = -1
		pendingTrimLen = 0
	}

	for i := int64(0); i < totalRuns; i++ {
		offset := i * ScanRunSize
		runLen := int64(ScanRunSize)
		if offset+runLen > deviceSize {
			runLen = deviceSize - offset
		}

		var hexHash string
		var isZeros bool

		if holes != nil && isRunInHole(holes, offset, offset+runLen) {
			hexHash = zerosHexForLen(runLen)
			isZeros = true
		} else {
			n, err := dev.ReadAt(buf[:runLen], offset)
			if err != nil && err != io.EOF {
				return nil, fmt.Errorf("reading at offset %d: %w", offset, err)
			}
			data := buf[:n]

			h := sha256.Sum256(data)
			hexHash = hex.EncodeToString(h[:])

			isZeros = (hexHash == zerosHexForLen(int64(n)))
		}

		if isZeros {
			var prevHash string
			err := selectStmt.QueryRow(offset).Scan(&prevHash)
			if err == nil && prevHash == hexHash {
				if pendingTrimStart >= 0 {
					pendingTrimLen += runLen
				}
				continue
			}
			if err != nil && err != sql.ErrNoRows {
				return nil, fmt.Errorf("querying hash at offset %d: %w", offset, err)
			}

			if pendingTrimStart < 0 {
				pendingTrimStart = i
				pendingTrimLen = runLen
			} else {
				pendingTrimLen += runLen
			}
			dbOps = append(dbOps, dbUpdate{offset: offset, hexHash: hexHash})
		} else {
			flushTrim()

			var prevHash string
			err := selectStmt.QueryRow(offset).Scan(&prevHash)
			if err == nil && prevHash == hexHash {
				continue
			}
			if err != nil && err != sql.ErrNoRows {
				return nil, fmt.Errorf("querying hash at offset %d: %w", offset, err)
			}

			dataCopy := make([]byte, runLen)
			copy(dataCopy, buf[:runLen])
			logEntries = append(logEntries, scanResult{
				block:  uint64(i) * ScanRunBlocks,
				data:   dataCopy,
				crc:    crc32.ChecksumIEEE(dataCopy),
				length: runLen,
			})
			dbOps = append(dbOps, dbUpdate{offset: offset, hexHash: hexHash})
		}
	}

	flushTrim()

	result := &ScanResult{
		TotalRuns:  totalRuns,
		DeviceSize: deviceSize,
	}

	// No changes
	if len(logEntries) == 0 {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("committing transaction: %w", err)
		}
		return result, nil
	}

	// Write log file
	label := TAI64NLabel()
	tmpPath := filepath.Join(cfg.LogDir, "disk."+label+".log.tmp")
	finalPath := filepath.Join(cfg.LogDir, "disk."+label+".log")

	outFile, err := os.Create(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("creating log file: %w", err)
	}

	hdr := Header{
		Version:      2,
		BlockSize:    ScanBlockSize,
		SegmentLabel: label,
		DeviceSize:   uint64(deviceSize),
		BackingPath:  cfg.DevicePath,
	}

	wr, err := NewWriter(outFile, hdr)
	if err != nil {
		outFile.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("writing log header: %w", err)
	}

	seq := 0
	for _, sr := range logEntries {
		if sr.isTrim {
			remaining := sr.length
			block := sr.block
			for remaining > 0 {
				chunk := remaining
				if chunk > int64(^uint32(0)) {
					chunk = int64(^uint32(0))
				}
				entry := &Entry{
					Op:          "T",
					TimestampNS: uint64(time.Now().UnixNano()),
					Sequence:    uint64(seq),
					Block:       block,
					Length:      uint32(chunk),
				}
				if err := wr.WriteEntry(entry); err != nil {
					outFile.Close()
					os.Remove(tmpPath)
					return nil, fmt.Errorf("writing entry %d: %w", seq, err)
				}
				seq++
				remaining -= chunk
				block += uint64(chunk) / ScanBlockSize
			}
			result.TrimCount++
		} else {
			entry := &Entry{
				Op:          "W",
				TimestampNS: uint64(time.Now().UnixNano()),
				Sequence:    uint64(seq),
				Block:       sr.block,
				Length:      uint32(len(sr.data)),
				Checksum:    sr.crc,
				Data:        sr.data,
			}
			if err := wr.WriteEntry(entry); err != nil {
				outFile.Close()
				os.Remove(tmpPath)
				return nil, fmt.Errorf("writing entry %d: %w", seq, err)
			}
			seq++
			result.WriteBytes += uint64(len(sr.data))
			result.WriteCount++
		}
	}

	if err := outFile.Close(); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("closing log file: %w", err)
	}

	// Crash-safety: rename log file BEFORE committing DB
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return nil, fmt.Errorf("renaming log file: %w", err)
	}

	result.LogPath = finalPath

	// Update DB
	upsertStmt, err := tx.Prepare(`INSERT INTO run_hashes (run_offset, sha256) VALUES (?, ?)
		ON CONFLICT(run_offset) DO UPDATE SET sha256 = excluded.sha256`)
	if err != nil {
		return nil, fmt.Errorf("preparing upsert: %w", err)
	}
	defer upsertStmt.Close()

	for _, op := range dbOps {
		if _, err := upsertStmt.Exec(op.offset, op.hexHash); err != nil {
			return nil, fmt.Errorf("updating hash at offset %d: %w", op.offset, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}

	return result, nil
}
