// Command lbdlog reads and prints LBD CBOR log files.
//
// Usage:
//
//	lbdlog show <logfile> [logfile...]
//	lbdlog replay <log-dir> <output-file>
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/evanphx/lbd/lbdlog"
	"miren.dev/mflags"
	_ "modernc.org/sqlite"
)

const (
	scanBlockSize = 4096
	scanRunBlocks = 15
	scanRunSize   = scanRunBlocks * scanBlockSize // 61440

	// lseek whence values for hole detection (Linux/macOS)
	_SEEK_DATA = 3
	_SEEK_HOLE = 4
)

// holeRange represents a contiguous hole (unallocated) region in a file.
type holeRange struct {
	start, end int64 // [start, end) byte offsets
}

// buildHoleMap uses SEEK_DATA/SEEK_HOLE to find all hole regions in a file.
// Returns nil if the filesystem doesn't support SEEK_HOLE (block devices, etc.),
// in which case the caller should skip hole processing entirely.
func buildHoleMap(f *os.File, size int64) []holeRange {
	if size == 0 {
		return nil
	}

	var holes []holeRange
	pos := int64(0)

	for pos < size {
		// Find next data at or after pos
		dataPos, err := f.Seek(pos, _SEEK_DATA)
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
		holePos, err := f.Seek(dataPos, _SEEK_HOLE)
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

func fmtSize(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func printLog(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	rd, err := lbdlog.NewReader(f)
	if err != nil {
		return fmt.Errorf("read header: %w", err)
	}

	h := rd.Header
	fmt.Printf("=== LBD Log: %s ===\n", path)
	fmt.Printf("Version:      %d\n", h.Version)
	fmt.Printf("Block size:   %d\n", h.BlockSize)
	fmt.Printf("Segment:      %s\n", h.SegmentLabel)
	fmt.Printf("Device size:  %s (%d bytes)\n", fmtSize(h.DeviceSize), h.DeviceSize)
	fmt.Printf("Backing file: %s\n", h.BackingPath)
	fmt.Println()

	count := 0
	for {
		e, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("entry %d: %w", count, err)
		}

		ts := time.Unix(0, int64(e.TimestampNS)).UTC()

		var label string
		if e.IsWrite() {
			label = "WRITE"
		} else if e.IsTrim() {
			label = "TRIM"
		} else if e.IsSnapshotCreate() {
			label = "SNAPSHOT CREATE"
		} else if e.IsSnapshotDelete() {
			label = "SNAPSHOT DELETE"
		} else {
			label = "UNKNOWN(" + e.Op + ")"
		}

		fmt.Printf("--- Entry #%d [%s] ---\n", e.Sequence, label)
		fmt.Printf("  Time:     %s UTC\n", ts.Format("2006-01-02 15:04:05.000000000"))

		if e.IsSnapshotCreate() {
			fmt.Printf("  Name:     %q\n", e.SnapshotCreateName())
			fmt.Println()
			count++
			continue
		}
		if e.IsSnapshotDelete() {
			fmt.Printf("  ID:       %d\n", e.SnapshotDeleteID())
			fmt.Println()
			count++
			continue
		}

		blocks := uint64(e.Length) / uint64(h.BlockSize)
		blockEnd := e.Block + blocks - 1
		offsetStart := e.Block * uint64(h.BlockSize)
		offsetEnd := offsetStart + uint64(e.Length) - 1

		fmt.Printf("  Extent:   %d-%d (%d blocks)\n", e.Block, blockEnd, blocks)
		fmt.Printf("  Offset:   0x%x-0x%x\n", offsetStart, offsetEnd)
		fmt.Printf("  Length:   %s (%d bytes)\n", fmtSize(uint64(e.Length)), e.Length)

		if e.IsWrite() {
			if e.CompressedSize > 0 {
				ratio := (1.0 - float64(e.CompressedSize)/float64(e.Length)) * 100.0
				fmt.Printf("  LZ4:      %s compressed (%.1f%% reduction)\n",
					fmtSize(uint64(e.CompressedSize)), ratio)
			}

			crcOK := e.ValidateCRC()
			status := "(OK)"
			if !crcOK {
				status = "(MISMATCH)"
			}
			fmt.Printf("  CRC32:    0x%08x %s\n", e.Checksum, status)

			// Show first 64 bytes of data as hex
			show := e.Data
			if len(show) > 64 {
				show = show[:64]
			}
			fmt.Printf("  Data[:%d]: %s", len(show), hex.EncodeToString(show))
			if len(e.Data) > 64 {
				fmt.Printf("...")
			}
			fmt.Println()
		}

		fmt.Println()
		count++
	}

	fmt.Printf("Total entries: %d\n", count)
	return nil
}

type showArgs struct {
	Files []string `rest:"true" usage:"log files to display"`
}

func runShow(cfg *showArgs) error {
	if len(cfg.Files) == 0 {
		return fmt.Errorf("at least one log file required")
	}
	for _, path := range cfg.Files {
		if err := printLog(path); err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
	}
	return nil
}

type replayArgs struct {
	QCow2      bool   `long:"qcow2" usage:"output as qcow2-lz4 image instead of flat file"`
	LogDir     string `position:"0" usage:"directory containing log files"`
	OutputPath string `position:"1" usage:"path to write reconstructed backing file"`
}

func runReplay(cfg *replayArgs) error {
	logDir := cfg.LogDir
	outputPath := cfg.OutputPath

	// Step A: Discover and sort log files
	dirEntries, err := os.ReadDir(logDir)
	if err != nil {
		return fmt.Errorf("reading log directory: %w", err)
	}

	var logFiles []string
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".log.tmp") {
			logFiles = append(logFiles, filepath.Join(logDir, name))
		}
	}

	sort.Strings(logFiles)

	if len(logFiles) == 0 {
		return fmt.Errorf("no log files found in %s", logDir)
	}

	// Step B: Read first header for device metadata
	firstFile, err := os.Open(logFiles[0])
	if err != nil {
		return fmt.Errorf("opening first log file: %w", err)
	}

	firstRd, err := lbdlog.NewReader(firstFile)
	if err != nil {
		firstFile.Close()
		return fmt.Errorf("reading header from %s: %w", logFiles[0], err)
	}

	deviceSize := firstRd.Header.DeviceSize
	blockSize := firstRd.Header.BlockSize
	firstFile.Close()

	// Step C: Create output and replay
	if cfg.QCow2 {
		return replayToQCow2(logFiles, outputPath, deviceSize, blockSize)
	}
	return replayToFlat(logFiles, outputPath, deviceSize, blockSize)
}

func replayToFlat(logFiles []string, outputPath string, deviceSize uint64, blockSize uint32) error {
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer outFile.Close()

	if err := outFile.Truncate(int64(deviceSize)); err != nil {
		return fmt.Errorf("setting output file size: %w", err)
	}

	var totalEntries, totalWrites, totalTrims, crcErrors int
	var totalBytes uint64

	for _, logPath := range logFiles {
		f, err := os.Open(logPath)
		if err != nil {
			return fmt.Errorf("opening %s: %w", logPath, err)
		}

		rd, err := lbdlog.NewReader(f)
		if err != nil {
			f.Close()
			return fmt.Errorf("reading header from %s: %w", logPath, err)
		}

		for {
			e, err := rd.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				return fmt.Errorf("reading entry from %s: %w", logPath, err)
			}

			totalEntries++

			if e.IsSnapshotCreate() || e.IsSnapshotDelete() {
				// Flat files don't support snapshots — skip
				continue
			}

			offset := int64(e.Block) * int64(blockSize)

			if e.IsWrite() {
				if !e.ValidateCRC() {
					crcErrors++
					fmt.Fprintf(os.Stderr, "Warning: CRC mismatch at entry seq=%d in %s\n", e.Sequence, logPath)
				}
				if _, err := outFile.WriteAt(e.Data, offset); err != nil {
					f.Close()
					return fmt.Errorf("writing at offset %d: %w", offset, err)
				}
				totalWrites++
				totalBytes += uint64(len(e.Data))
			} else if e.IsTrim() {
				const (
					fallocPunchHole = 0x02 // FALLOC_FL_PUNCH_HOLE
					fallocKeepSize  = 0x01 // FALLOC_FL_KEEP_SIZE
				)
				fd := int(outFile.Fd())
				err := syscall.Fallocate(fd,
					fallocPunchHole|fallocKeepSize,
					offset, int64(e.Length))
				if err != nil {
					f.Close()
					return fmt.Errorf("punching hole at offset %d: %w", offset, err)
				}
				totalTrims++
				totalBytes += uint64(e.Length)
			}
		}

		f.Close()
	}

	fmt.Printf("Replayed %d entries (%d writes, %d trims) from %d segments\n",
		totalEntries, totalWrites, totalTrims, len(logFiles))
	fmt.Printf("Output: %s (%s)\n", outputPath, fmtSize(deviceSize))
	fmt.Printf("CRC errors: %d\n", crcErrors)

	return nil
}

func replayToQCow2(logFiles []string, outputPath string, deviceSize uint64, blockSize uint32) error {
	img, err := lbdlog.CreateQCow2(outputPath, deviceSize, 16)
	if err != nil {
		return fmt.Errorf("creating qcow2 image: %w", err)
	}

	var totalEntries, totalWrites, totalTrims, crcErrors int
	var totalBytes uint64

	for _, logPath := range logFiles {
		f, err := os.Open(logPath)
		if err != nil {
			img.Close()
			return fmt.Errorf("opening %s: %w", logPath, err)
		}

		rd, err := lbdlog.NewReader(f)
		if err != nil {
			f.Close()
			img.Close()
			return fmt.Errorf("reading header from %s: %w", logPath, err)
		}

		for {
			e, err := rd.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				img.Close()
				return fmt.Errorf("reading entry from %s: %w", logPath, err)
			}

			totalEntries++

			if e.IsSnapshotCreate() || e.IsSnapshotDelete() {
				// Internal snapshots not supported — skip
				continue
			}

			offset := int64(e.Block) * int64(blockSize)

			if e.IsWrite() {
				if !e.ValidateCRC() {
					crcErrors++
					fmt.Fprintf(os.Stderr, "Warning: CRC mismatch at entry seq=%d in %s\n", e.Sequence, logPath)
				}
				if _, err := img.WriteAt(e.Data, offset); err != nil {
					f.Close()
					img.Close()
					return fmt.Errorf("writing at offset %d: %w", offset, err)
				}
				totalWrites++
				totalBytes += uint64(len(e.Data))
			} else if e.IsTrim() {
				if err := img.Trim(offset, int(e.Length)); err != nil {
					f.Close()
					img.Close()
					return fmt.Errorf("trimming at offset %d: %w", offset, err)
				}
				totalTrims++
				totalBytes += uint64(e.Length)
			}
		}

		f.Close()
	}

	if err := img.Close(); err != nil {
		return fmt.Errorf("closing qcow2 image: %w", err)
	}

	fmt.Printf("Replayed %d entries (%d writes, %d trims) from %d segments\n",
		totalEntries, totalWrites, totalTrims, len(logFiles))
	fmt.Printf("Output: %s (qcow2-lz4, virtual %s)\n", outputPath, fmtSize(deviceSize))
	fmt.Printf("CRC errors: %d\n", crcErrors)

	return nil
}

func tai64nLabel() string {
	now := time.Now()
	taiSecs := uint64(now.Unix()) + 0x4000000000000000
	return fmt.Sprintf("%016x%08x", taiSecs, now.Nanosecond())
}

type repackArgs struct {
	Inplace  bool   `long:"inplace" usage:"write repacked file into log dir and remove old segments"`
	LogDir   string `position:"0" usage:"directory containing log segment files"`
	OutputDir string `position:"1" usage:"directory to write repacked log file"`
}

func discoverLogFiles(dir string) ([]string, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading log directory: %w", err)
	}

	var logFiles []string
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if strings.HasSuffix(name, ".log.tmp") {
			continue
		}
		if strings.HasSuffix(name, ".log") {
			logFiles = append(logFiles, filepath.Join(dir, name))
		}
	}

	sort.Strings(logFiles)
	return logFiles, nil
}

func runRepack(cfg *repackArgs) error {
	if !cfg.Inplace && cfg.OutputDir == "" {
		return fmt.Errorf("output directory required (or use --inplace)")
	}

	// Step 1: Discover .log files, skip .log.tmp
	logFiles, err := discoverLogFiles(cfg.LogDir)
	if err != nil {
		return err
	}

	if len(logFiles) == 0 {
		return fmt.Errorf("no .log files found in %s", cfg.LogDir)
	}

	// Step 2: Read header from first file for device metadata
	firstFile, err := os.Open(logFiles[0])
	if err != nil {
		return fmt.Errorf("opening first log file: %w", err)
	}

	firstRd, err := lbdlog.NewReader(firstFile)
	if err != nil {
		firstFile.Close()
		return fmt.Errorf("reading header from %s: %w", logFiles[0], err)
	}

	label := tai64nLabel()

	outHdr := lbdlog.Header{
		Version:      firstRd.Header.Version,
		BlockSize:    firstRd.Header.BlockSize,
		SegmentLabel: label,
		DeviceSize:   firstRd.Header.DeviceSize,
		BackingPath:  firstRd.Header.BackingPath,
	}
	firstFile.Close()

	// Step 3: Determine output path
	outDir := cfg.OutputDir
	if cfg.Inplace {
		outDir = cfg.LogDir
	}

	tmpPath := filepath.Join(outDir, "disk."+label+".log.tmp")

	outFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer outFile.Close()

	wr, err := lbdlog.NewWriter(outFile, outHdr)
	if err != nil {
		return fmt.Errorf("writing output header: %w", err)
	}

	// Step 4: Read all input files and write entries to output
	var totalEntries int

	for _, logPath := range logFiles {
		f, err := os.Open(logPath)
		if err != nil {
			return fmt.Errorf("opening %s: %w", logPath, err)
		}

		rd, err := lbdlog.NewReader(f)
		if err != nil {
			f.Close()
			return fmt.Errorf("reading header from %s: %w", logPath, err)
		}

		for {
			e, err := rd.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				return fmt.Errorf("reading entry from %s: %w", logPath, err)
			}

			if err := wr.WriteEntry(e); err != nil {
				f.Close()
				return fmt.Errorf("writing entry: %w", err)
			}
			totalEntries++
		}

		f.Close()
	}

	// Step 5: Rename tmp to final; for --inplace also remove old segments
	finalPath := filepath.Join(outDir, "disk."+label+".log")
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("renaming temp file: %w", err)
	}

	if cfg.Inplace {
		for _, logPath := range logFiles {
			if err := os.Remove(logPath); err != nil {
				return fmt.Errorf("removing old segment %s: %w", logPath, err)
			}
		}
	}

	fmt.Printf("Repacked %d entries from %d files into %s\n", totalEntries, len(logFiles), finalPath)

	return nil
}

type scanArgs struct {
	DB         string `long:"db" usage:"path to SQLite hash database"`
	LogDir     string `long:"log-dir" usage:"directory to write log segment files"`
	DevicePath string `position:"0" usage:"block device or file to scan"`
}

func runScan(cfg *scanArgs) error {
	if cfg.DB == "" {
		return fmt.Errorf("--db is required")
	}
	if cfg.LogDir == "" {
		return fmt.Errorf("--log-dir is required")
	}
	if cfg.DevicePath == "" {
		return fmt.Errorf("device path is required")
	}

	// Open device read-only and determine size
	dev, err := os.Open(cfg.DevicePath)
	if err != nil {
		return fmt.Errorf("opening device: %w", err)
	}
	defer dev.Close()

	deviceSize, err := dev.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("seeking to end: %w", err)
	}

	// Build hole map using SEEK_DATA/SEEK_HOLE (nil if unsupported)
	holes := buildHoleMap(dev, deviceSize)

	// Open/create SQLite DB
	db, err := sql.Open("sqlite", cfg.DB)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return fmt.Errorf("setting journal mode: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS run_hashes (
		run_offset INTEGER PRIMARY KEY,
		sha256     TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("creating table: %w", err)
	}

	// Compute total runs
	totalRuns := deviceSize / scanRunSize
	if deviceSize%scanRunSize != 0 {
		totalRuns++
	}

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	selectStmt, err := tx.Prepare("SELECT sha256 FROM run_hashes WHERE run_offset = ?")
	if err != nil {
		return fmt.Errorf("preparing select: %w", err)
	}
	defer selectStmt.Close()

	// Precompute zeros hash for full-size runs
	zerosFullBuf := make([]byte, scanRunSize)
	zerosFullSha := sha256.Sum256(zerosFullBuf)
	zerosFullHex := hex.EncodeToString(zerosFullSha[:])

	// Helper to get zeros hash for a given length
	zerosHexForLen := func(length int64) string {
		if length == scanRunSize {
			return zerosFullHex
		}
		buf := make([]byte, length)
		h := sha256.Sum256(buf)
		return hex.EncodeToString(h[:])
	}

	// Scan results — writes and coalesced trims, in offset order
	type scanResult struct {
		block  uint64 // starting block number
		isTrim bool
		data   []byte // nil for trims
		crc    uint32
		length int64 // may span multiple runs for coalesced trims
	}

	// DB updates — all upserts (zeros hash for trims, data hash for writes)
	type dbUpdate struct {
		offset  int64
		hexHash string
	}

	var logEntries []scanResult
	var dbOps []dbUpdate
	buf := make([]byte, scanRunSize)

	// Inline trim coalescing state
	pendingTrimStart := int64(-1) // run index where current trim chain started
	pendingTrimLen := int64(0)    // accumulated byte length

	flushTrim := func() {
		if pendingTrimStart < 0 {
			return
		}
		logEntries = append(logEntries, scanResult{
			block:  uint64(pendingTrimStart) * scanRunBlocks,
			isTrim: true,
			length: pendingTrimLen,
		})
		pendingTrimStart = -1
		pendingTrimLen = 0
	}

	for i := int64(0); i < totalRuns; i++ {
		offset := i * scanRunSize
		runLen := int64(scanRunSize)
		if offset+runLen > deviceSize {
			runLen = deviceSize - offset
		}

		var hexHash string
		var isZeros bool

		if holes != nil && isRunInHole(holes, offset, offset+runLen) {
			// Hole run — use precomputed zeros hash, skip reading
			hexHash = zerosHexForLen(runLen)
			isZeros = true
		} else {
			// Data run — read and hash
			n, err := dev.ReadAt(buf[:runLen], offset)
			if err != nil && err != io.EOF {
				return fmt.Errorf("reading at offset %d: %w", offset, err)
			}
			data := buf[:n]

			h := sha256.Sum256(data)
			hexHash = hex.EncodeToString(h[:])

			// Check if data is all zeros by comparing hash
			isZeros = (hexHash == zerosHexForLen(int64(n)))
		}

		if isZeros {
			// Zeros path (hole or all-zeros data)
			var prevHash string
			err := selectStmt.QueryRow(offset).Scan(&prevHash)
			if err == nil && prevHash == hexHash {
				// DB already has zeros hash — extend active trim chain, otherwise skip
				if pendingTrimStart >= 0 {
					pendingTrimLen += runLen
				}
				continue
			}
			if err != nil && err != sql.ErrNoRows {
				return fmt.Errorf("querying hash at offset %d: %w", offset, err)
			}

			// DB hash differs or missing — start/extend trim chain, record DB upsert
			if pendingTrimStart < 0 {
				pendingTrimStart = i
				pendingTrimLen = runLen
			} else {
				pendingTrimLen += runLen
			}
			dbOps = append(dbOps, dbUpdate{offset: offset, hexHash: hexHash})
		} else {
			// Non-zero data path — flush any pending trim chain
			flushTrim()

			// Check DB hash for change detection
			var prevHash string
			err := selectStmt.QueryRow(offset).Scan(&prevHash)
			if err == nil && prevHash == hexHash {
				continue // unchanged
			}
			if err != nil && err != sql.ErrNoRows {
				return fmt.Errorf("querying hash at offset %d: %w", offset, err)
			}

			// Changed or new — copy data and record
			dataCopy := make([]byte, runLen)
			copy(dataCopy, buf[:runLen])
			logEntries = append(logEntries, scanResult{
				block:  uint64(i) * scanRunBlocks,
				data:   dataCopy,
				crc:    crc32.ChecksumIEEE(dataCopy),
				length: runLen,
			})
			dbOps = append(dbOps, dbUpdate{offset: offset, hexHash: hexHash})
		}
	}

	// Flush any trailing trim chain
	flushTrim()

	// No changes
	if len(logEntries) == 0 {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing transaction: %w", err)
		}
		fmt.Printf("Scanned %d runs (%s) — no changes detected\n",
			totalRuns, fmtSize(uint64(deviceSize)))
		return nil
	}

	// Write log file
	label := tai64nLabel()
	tmpPath := filepath.Join(cfg.LogDir, "disk."+label+".log.tmp")
	finalPath := filepath.Join(cfg.LogDir, "disk."+label+".log")

	outFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("creating log file: %w", err)
	}

	hdr := lbdlog.Header{
		Version:      2,
		BlockSize:    scanBlockSize,
		SegmentLabel: label,
		DeviceSize:   uint64(deviceSize),
		BackingPath:  cfg.DevicePath,
	}

	wr, err := lbdlog.NewWriter(outFile, hdr)
	if err != nil {
		outFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("writing log header: %w", err)
	}

	var totalWriteBytes uint64
	var trimCount, writeCount int
	seq := 0
	for _, sr := range logEntries {
		if sr.isTrim {
			// Split coalesced trim into uint32-sized entries if needed
			remaining := sr.length
			block := sr.block
			for remaining > 0 {
				chunk := remaining
				if chunk > int64(^uint32(0)) {
					chunk = int64(^uint32(0))
				}
				entry := &lbdlog.Entry{
					Op:          "T",
					TimestampNS: uint64(time.Now().UnixNano()),
					Sequence:    uint64(seq),
					Block:       block,
					Length:      uint32(chunk),
				}
				if err := wr.WriteEntry(entry); err != nil {
					outFile.Close()
					os.Remove(tmpPath)
					return fmt.Errorf("writing entry %d: %w", seq, err)
				}
				seq++
				remaining -= chunk
				block += uint64(chunk) / scanBlockSize
			}
			trimCount++
		} else {
			entry := &lbdlog.Entry{
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
				return fmt.Errorf("writing entry %d: %w", seq, err)
			}
			seq++
			totalWriteBytes += uint64(len(sr.data))
			writeCount++
		}
	}

	if err := outFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("closing log file: %w", err)
	}

	// Crash-safety: rename log file BEFORE committing DB
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("renaming log file: %w", err)
	}

	// Update DB: all upserts (zeros hash for trims, data hash for writes)
	upsertStmt, err := tx.Prepare(`INSERT INTO run_hashes (run_offset, sha256) VALUES (?, ?)
		ON CONFLICT(run_offset) DO UPDATE SET sha256 = excluded.sha256`)
	if err != nil {
		return fmt.Errorf("preparing upsert: %w", err)
	}
	defer upsertStmt.Close()

	for _, op := range dbOps {
		if _, err := upsertStmt.Exec(op.offset, op.hexHash); err != nil {
			return fmt.Errorf("updating hash at offset %d: %w", op.offset, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}

	fmt.Printf("Scanned %d runs, %d changed, %d trimmed (%s written) → %s\n",
		totalRuns, writeCount, trimCount, fmtSize(totalWriteBytes), finalPath)
	return nil
}

// interval represents a half-open range [lo, hi) of block numbers.
type interval struct {
	lo, hi uint64
}

// blockSet tracks covered block ranges as sorted, non-overlapping, non-adjacent
// [lo, hi) intervals. Used to determine which blocks are shadowed by later entries.
type blockSet struct {
	intervals []interval
}

// add inserts the range [lo, hi) into the set, merging with any
// overlapping or adjacent existing intervals.
func (bs *blockSet) add(lo, hi uint64) {
	// Find all intervals that overlap or are adjacent to [lo, hi).
	// An interval iv overlaps/is adjacent if iv.lo <= hi && iv.hi >= lo.
	first := -1
	last := -1
	for i, iv := range bs.intervals {
		if iv.lo <= hi && iv.hi >= lo {
			if first == -1 {
				first = i
			}
			last = i
		}
	}

	if first == -1 {
		// No overlap — insert in sorted position.
		pos := sort.Search(len(bs.intervals), func(i int) bool {
			return bs.intervals[i].lo >= lo
		})
		bs.intervals = append(bs.intervals, interval{})
		copy(bs.intervals[pos+1:], bs.intervals[pos:])
		bs.intervals[pos] = interval{lo, hi}
		return
	}

	// Merge: expand to cover [lo, hi) and all overlapping intervals.
	merged := interval{lo, hi}
	if bs.intervals[first].lo < merged.lo {
		merged.lo = bs.intervals[first].lo
	}
	if bs.intervals[last].hi > merged.hi {
		merged.hi = bs.intervals[last].hi
	}

	bs.intervals[first] = merged
	// Remove intervals [first+1, last].
	if last > first {
		bs.intervals = append(bs.intervals[:first+1], bs.intervals[last+1:]...)
	}
}

// uncovered returns the sub-ranges of [lo, hi) NOT covered by any interval
// in the set. The result is a list of non-overlapping intervals in ascending order.
func (bs *blockSet) uncovered(lo, hi uint64) []interval {
	var gaps []interval
	cursor := lo

	for _, iv := range bs.intervals {
		if iv.hi <= cursor {
			continue // entirely before cursor
		}
		if iv.lo >= hi {
			break // past our range
		}
		// iv overlaps [cursor, hi)
		if cursor < iv.lo {
			gaps = append(gaps, interval{cursor, iv.lo})
		}
		if iv.hi > cursor {
			cursor = iv.hi
		}
	}

	if cursor < hi {
		gaps = append(gaps, interval{cursor, hi})
	}
	return gaps
}

// coversAll reports whether [lo, hi) is fully contained in a single interval.
func (bs *blockSet) coversAll(lo, hi uint64) bool {
	// Binary search for the first interval whose hi > lo.
	idx := sort.Search(len(bs.intervals), func(i int) bool {
		return bs.intervals[i].hi > lo
	})
	if idx >= len(bs.intervals) {
		return false
	}
	iv := bs.intervals[idx]
	return iv.lo <= lo && iv.hi >= hi
}

type gcArgs struct {
	Threshold float64 `long:"threshold" usage:"utilization threshold (0.0-1.0) below which segments are retired"`
	DryRun    bool    `long:"dry-run" usage:"show utilization without retiring segments"`
	LogDir    string  `position:"0" usage:"directory containing log segment files"`
}

type entryMeta struct {
	segIndex   int
	entryIndex int
	block      uint64
	numBlocks  uint64
	isWrite    bool
	isSnapshot bool
	dataLen    uint32
	liveRanges []interval
}

type segmentStats struct {
	path            string
	totalWriteBytes uint64
	liveWriteBytes  uint64
	totalEntries    int
	liveEntries     int
}

type entryKey struct {
	segIndex, entryIndex int
}

func runGC(cfg *gcArgs) error {
	if cfg.LogDir == "" {
		return fmt.Errorf("log directory is required")
	}

	threshold := cfg.Threshold
	if threshold == 0 {
		threshold = 0.5
	}

	// Discover segments.
	logFiles, err := discoverLogFiles(cfg.LogDir)
	if err != nil {
		return err
	}
	if len(logFiles) == 0 {
		return fmt.Errorf("no .log files found in %s", cfg.LogDir)
	}

	// --- Pass 1: Analyze ---

	// Read all entries from all segments; record metadata, discard Data.
	var allMeta []entryMeta
	stats := make([]segmentStats, len(logFiles))

	var firstHeader lbdlog.Header

	for si, logPath := range logFiles {
		stats[si].path = logPath

		f, err := os.Open(logPath)
		if err != nil {
			return fmt.Errorf("opening %s: %w", logPath, err)
		}

		rd, err := lbdlog.NewReader(f)
		if err != nil {
			f.Close()
			return fmt.Errorf("reading header from %s: %w", logPath, err)
		}

		if si == 0 {
			firstHeader = rd.Header
		}

		ei := 0
		for {
			e, err := rd.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				return fmt.Errorf("reading entry from %s: %w", logPath, err)
			}

			numBlocks := uint64(e.Length) / uint64(rd.Header.BlockSize)
			if numBlocks == 0 {
				numBlocks = 1
			}

			m := entryMeta{
				segIndex:   si,
				entryIndex: ei,
				block:      e.Block,
				numBlocks:  numBlocks,
				isWrite:    e.IsWrite(),
				isSnapshot: e.IsSnapshotCreate() || e.IsSnapshotDelete(),
				dataLen:    e.Length,
			}
			allMeta = append(allMeta, m)

			if e.IsWrite() {
				stats[si].totalWriteBytes += uint64(e.Length)
			}
			stats[si].totalEntries++

			ei++
		}

		f.Close()
	}

	// Process entries in reverse order (newest first) to determine liveness.
	var covered blockSet
	blockSize := firstHeader.BlockSize
	for i := len(allMeta) - 1; i >= 0; i-- {
		m := &allMeta[i]
		if m.isSnapshot {
			// Snapshot markers are always live — they must be preserved
			m.liveRanges = []interval{{0, 1}}
			continue
		}
		lo := m.block
		hi := lo + m.numBlocks
		liveRanges := covered.uncovered(lo, hi)
		m.liveRanges = liveRanges
		if len(liveRanges) > 0 {
			covered.add(lo, hi)
		}
	}

	// Accumulate per-segment live stats.
	for i := range allMeta {
		m := &allMeta[i]
		if len(m.liveRanges) > 0 {
			stats[m.segIndex].liveEntries++
			if m.isWrite {
				for _, r := range m.liveRanges {
					stats[m.segIndex].liveWriteBytes += (r.hi - r.lo) * uint64(blockSize)
				}
			}
		}
	}

	// Print table.
	fmt.Printf("%-40s %7s %5s %10s %10s %7s\n",
		"SEGMENT", "ENTRIES", "LIVE", "WRITE", "LIVE WRITE", "UTIL")
	fmt.Println(strings.Repeat("-", 86))

	var retireIndexes []int

	for si, s := range stats {
		name := filepath.Base(s.path)
		util := 1.0
		if s.totalWriteBytes > 0 {
			util = float64(s.liveWriteBytes) / float64(s.totalWriteBytes)
		}
		tag := ""
		if util < threshold && s.totalWriteBytes > 0 {
			tag = " [RETIRE]"
			retireIndexes = append(retireIndexes, si)
		}
		fmt.Printf("%-40s %7d %5d %10s %10s %6.1f%%%s\n",
			name, s.totalEntries, s.liveEntries,
			fmtSize(s.totalWriteBytes), fmtSize(s.liveWriteBytes),
			util*100.0, tag)
	}
	fmt.Println()

	if len(retireIndexes) == 0 {
		fmt.Printf("No segments below %.0f%% utilization threshold.\n", threshold*100.0)
		return nil
	}

	fmt.Printf("%d segment(s) below %.0f%% utilization threshold.\n",
		len(retireIndexes), threshold*100.0)

	if cfg.DryRun {
		return nil
	}

	// --- Pass 2: Retire ---

	// Build set of live entries in retired segments for O(1) lookup.
	liveSet := make(map[entryKey][]interval)
	for i := range allMeta {
		m := &allMeta[i]
		if len(m.liveRanges) == 0 {
			continue
		}
		// Check if this entry belongs to a retired segment.
		for _, ri := range retireIndexes {
			if m.segIndex == ri {
				liveSet[entryKey{m.segIndex, m.entryIndex}] = m.liveRanges
				break
			}
		}
	}

	// If no live entries to copy, just delete the retired segments.
	if len(liveSet) == 0 {
		for _, ri := range retireIndexes {
			if err := os.Remove(stats[ri].path); err != nil {
				return fmt.Errorf("removing %s: %w", stats[ri].path, err)
			}
		}
		fmt.Printf("Retired %d segment(s): no live entries to copy.\n", len(retireIndexes))
		return nil
	}

	label := tai64nLabel()
	tmpPath := filepath.Join(cfg.LogDir, "disk."+label+".log.tmp")
	finalPath := filepath.Join(cfg.LogDir, "disk."+label+".log")

	outFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}

	outHdr := lbdlog.Header{
		Version:      firstHeader.Version,
		BlockSize:    firstHeader.BlockSize,
		SegmentLabel: label,
		DeviceSize:   firstHeader.DeviceSize,
		BackingPath:  firstHeader.BackingPath,
	}

	wr, err := lbdlog.NewWriter(outFile, outHdr)
	if err != nil {
		outFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("writing output header: %w", err)
	}

	var copiedEntries int
	var copiedBytes uint64
	seq := uint64(0)

	for _, ri := range retireIndexes {
		f, err := os.Open(stats[ri].path)
		if err != nil {
			outFile.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("opening %s: %w", stats[ri].path, err)
		}

		rd, err := lbdlog.NewReader(f)
		if err != nil {
			f.Close()
			outFile.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("reading header from %s: %w", stats[ri].path, err)
		}

		ei := 0
		for {
			e, err := rd.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				outFile.Close()
				os.Remove(tmpPath)
				return fmt.Errorf("reading entry from %s: %w", stats[ri].path, err)
			}

			if _, ok := liveSet[entryKey{ri, ei}]; ok {
				if e.IsSnapshotCreate() || e.IsSnapshotDelete() {
					// Copy snapshot markers verbatim
					copyEntry := &lbdlog.Entry{
						Op:          e.Op,
						TimestampNS: e.TimestampNS,
						Sequence:    seq,
						SnapName:    e.SnapName,
					}
					seq++
					if err := wr.WriteEntry(copyEntry); err != nil {
						f.Close()
						outFile.Close()
						os.Remove(tmpPath)
						return fmt.Errorf("writing entry: %w", err)
					}
					copiedEntries++
				} else {
					ranges := liveSet[entryKey{ri, ei}]
					for _, r := range ranges {
						splitEntry := &lbdlog.Entry{
							Op:          e.Op,
							TimestampNS: uint64(time.Now().UnixNano()),
							Sequence:    seq,
							Block:       r.lo,
						}
						seq++
						if e.IsWrite() {
							dataStart := (r.lo - e.Block) * uint64(blockSize)
							dataEnd := (r.hi - e.Block) * uint64(blockSize)
							slice := e.Data[dataStart:dataEnd]
							splitEntry.Length = uint32(len(slice))
							splitEntry.Checksum = crc32.ChecksumIEEE(slice)
							splitEntry.Data = slice
						} else {
							splitEntry.Length = uint32((r.hi - r.lo) * uint64(blockSize))
						}
						if err := wr.WriteEntry(splitEntry); err != nil {
							f.Close()
							outFile.Close()
							os.Remove(tmpPath)
							return fmt.Errorf("writing entry: %w", err)
						}
						copiedEntries++
						if e.IsWrite() {
							copiedBytes += uint64(splitEntry.Length)
						}
					}
				}
			}

			ei++
		}

		f.Close()
	}

	if err := outFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("closing output file: %w", err)
	}

	// Atomic rename: new segment on disk before any deletes.
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("renaming temp file: %w", err)
	}

	// Delete retired segments.
	for _, ri := range retireIndexes {
		if err := os.Remove(stats[ri].path); err != nil {
			return fmt.Errorf("removing %s: %w", stats[ri].path, err)
		}
	}

	fmt.Printf("Retired %d segment(s): copied %d live entries (%s) into %s\n",
		len(retireIndexes), copiedEntries, fmtSize(copiedBytes),
		filepath.Base(finalPath))

	return nil
}

type sumArgs struct {
	Files []string `rest:"true" usage:"files to checksum (raw or qcow2)"`
}

func runSum(cfg *sumArgs) error {
	if len(cfg.Files) == 0 {
		return fmt.Errorf("at least one file required")
	}

	for _, path := range cfg.Files {
		hexHash, err := checksumFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Printf("%s  %s\n", hexHash, path)
	}
	return nil
}

func checksumFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Read first 8 bytes to check for qcow2 magic
	var magicBuf [8]byte
	if _, err := f.ReadAt(magicBuf[:], 0); err != nil {
		return "", fmt.Errorf("reading magic: %w", err)
	}

	magic := binary.BigEndian.Uint64(magicBuf[:])
	if magic == lbdlog.QCow2Magic {
		return checksumQCow2(f)
	}
	return checksumRaw(f)
}

func checksumRaw(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func checksumQCow2(f *os.File) (string, error) {
	img, err := lbdlog.OpenQCow2File(f)
	if err != nil {
		return "", err
	}
	img.SetReadOnly(true)

	h := sha256.New()
	buf := make([]byte, img.ClusterSize)
	remaining := int64(img.VirtualSize)
	offset := int64(0)

	for remaining > 0 {
		readLen := int64(img.ClusterSize)
		if readLen > remaining {
			readLen = remaining
		}

		n, err := img.ReadAt(buf[:readLen], offset)
		if err != nil {
			img.Close()
			return "", fmt.Errorf("reading at offset %d: %w", offset, err)
		}

		h.Write(buf[:n])
		offset += int64(n)
		remaining -= int64(n)
	}

	img.Close()
	return hex.EncodeToString(h.Sum(nil)), nil
}

func main() {
	d := mflags.NewDispatcher("lbdlog")
	d.Dispatch("show", mflags.Infer(runShow, mflags.WithUsage("Display log file contents")))
	d.Dispatch("replay", mflags.Infer(runReplay, mflags.WithUsage("Replay log files to reconstruct backing file")))
	d.Dispatch("repack", mflags.Infer(runRepack, mflags.WithUsage("Repack multiple log segments into a single file")))
	d.Dispatch("scan", mflags.Infer(runScan, mflags.WithUsage("Scan a device for changes and write log segments")))
	d.Dispatch("gc", mflags.Infer(runGC, mflags.WithUsage("Garbage-collect dead entries from log segments")))
	d.Dispatch("sum", mflags.Infer(runSum, mflags.WithUsage("Output SHA-256 checksum of file data (supports raw and qcow2)")))

	// Default to "show" if the first argument isn't a known subcommand
	args := os.Args[1:]
	if len(args) > 0 && args[0] != "show" && args[0] != "replay" && args[0] != "repack" && args[0] != "scan" && args[0] != "gc" && args[0] != "sum" {
		args = append([]string{"show"}, args...)
	}

	if err := d.Run(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
