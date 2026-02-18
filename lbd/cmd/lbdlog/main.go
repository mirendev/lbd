// Command lbdlog reads and prints LBD CBOR log files.
//
// Usage:
//
//	lbdlog show <logfile> [logfile...]
//	lbdlog replay <log-dir> <output-file>
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"hash/crc32"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/evanphx/lbd/lbd"
	"miren.dev/mflags"
	_ "modernc.org/sqlite"
)

// logSource represents a log file that can be opened for reading.
type logSource struct {
	Name string
	Open func() (io.ReadCloser, error)
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

	rd, err := lbd.NewReader(f)
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
		} else {
			label = "UNKNOWN(" + e.Op + ")"
		}

		fmt.Printf("--- Entry #%d [%s] ---\n", e.Sequence, label)
		fmt.Printf("  Time:     %s UTC\n", ts.Format("2006-01-02 15:04:05.000000000"))

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
	DB         string `long:"db" usage:"path to SQLite database for incremental replay"`
	S3Bucket   string `long:"s3-bucket" usage:"S3 bucket containing log files"`
	S3Prefix   string `long:"s3-prefix" usage:"S3 key prefix"`
	S3Endpoint string `long:"s3-endpoint" usage:"S3-compatible endpoint URL"`
	S3Region   string `long:"s3-region" usage:"AWS region for S3"`
	VolName    string `long:"vol-name" usage:"volume name (required with --s3-bucket)"`
	LogDir     string `position:"0" usage:"directory containing log files"`
	OutputPath string `position:"1" usage:"path to write reconstructed backing file"`
}

func runReplay(cfg *replayArgs) error {
	var logs []logSource
	var outputPath string

	if cfg.S3Bucket != "" {
		// S3 mode: position 0 is the output path
		if cfg.VolName == "" {
			return fmt.Errorf("--vol-name is required with --s3-bucket")
		}
		outputPath = cfg.LogDir // position 0
		if outputPath == "" {
			return fmt.Errorf("output path required")
		}

		ctx := context.Background()
		uploader, err := lbd.NewS3Uploader(ctx, lbd.S3UploaderConfig{
			Bucket:   cfg.S3Bucket,
			Prefix:   cfg.S3Prefix,
			Endpoint: cfg.S3Endpoint,
			Region:   cfg.S3Region,
		})
		if err != nil {
			return fmt.Errorf("creating S3 client: %w", err)
		}

		keys, err := uploader.ListLogs(ctx, cfg.VolName)
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			return fmt.Errorf("no log files found in s3://%s/%s", cfg.S3Bucket, cfg.VolName)
		}

		for _, k := range keys {
			key := k // capture for closure
			logs = append(logs, logSource{
				Name: "s3://" + cfg.S3Bucket + "/" + key,
				Open: func() (io.ReadCloser, error) {
					return uploader.OpenLog(ctx, key)
				},
			})
		}
	} else {
		// Local mode
		logDir := cfg.LogDir
		outputPath = cfg.OutputPath

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

		for _, p := range logFiles {
			path := p // capture for closure
			logs = append(logs, logSource{
				Name: path,
				Open: func() (io.ReadCloser, error) {
					return os.Open(path)
				},
			})
		}
	}

	// Incremental replay: filter logs to only new ones
	var db *sql.DB
	var lastReplayedLabel string
	if cfg.DB != "" {
		var err error
		db, err = lbd.OpenDB(cfg.DB)
		if err != nil {
			return fmt.Errorf("opening replay database: %w", err)
		}
		defer db.Close()

		lastReplayedLabel, err = lbd.GetLabel(db, "last_replayed_label")
		if err != nil {
			return err
		}
	}

	if lastReplayedLabel != "" {
		filtered := logs[:0]
		for _, l := range logs {
			label := lbd.LabelFromLogPath(l.Name)
			if label > lastReplayedLabel {
				filtered = append(filtered, l)
			}
		}
		logs = filtered

		if len(logs) == 0 {
			fmt.Println("No new log files to replay")
			return nil
		}
	}

	// Read first header for device metadata
	firstRC, err := logs[0].Open()
	if err != nil {
		return fmt.Errorf("opening first log file: %w", err)
	}

	firstRd, err := lbd.NewReader(firstRC)
	if err != nil {
		firstRC.Close()
		return fmt.Errorf("reading header from %s: %w", logs[0].Name, err)
	}

	deviceSize := firstRd.Header.DeviceSize
	blockSize := firstRd.Header.BlockSize
	firstRC.Close()

	incremental := lastReplayedLabel != ""

	// Create output and replay
	if cfg.QCow2 {
		err = replayToQCow2(logs, outputPath, deviceSize, blockSize, incremental)
	} else {
		err = replayToFlat(logs, outputPath, deviceSize, blockSize, incremental)
	}
	if err != nil {
		return err
	}

	// Record last replayed label
	if db != nil {
		lastLog := logs[len(logs)-1]
		label := lbd.LabelFromLogPath(lastLog.Name)
		if err := lbd.SetLabel(db, "last_replayed_label", label); err != nil {
			return err
		}
	}

	return nil
}

func replayToFlat(logs []logSource, outputPath string, deviceSize uint64, blockSize uint32, incremental bool) error {
	var outFile *os.File
	var err error

	if incremental {
		outFile, err = os.OpenFile(outputPath, os.O_RDWR, 0666)
		if err != nil {
			return fmt.Errorf("opening output file for incremental replay: %w", err)
		}
	} else {
		outFile, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		if err := outFile.Truncate(int64(deviceSize)); err != nil {
			outFile.Close()
			return fmt.Errorf("setting output file size: %w", err)
		}
	}
	defer outFile.Close()

	var totalEntries, totalWrites, totalTrims, crcErrors int
	var totalBytes uint64

	for _, log := range logs {
		f, err := log.Open()
		if err != nil {
			return fmt.Errorf("opening %s: %w", log.Name, err)
		}

		rd, err := lbd.NewReader(f)
		if err != nil {
			f.Close()
			return fmt.Errorf("reading header from %s: %w", log.Name, err)
		}

		for {
			e, err := rd.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				return fmt.Errorf("reading entry from %s: %w", log.Name, err)
			}

			totalEntries++
			offset := int64(e.Block) * int64(blockSize)

			if e.IsWrite() {
				if !e.ValidateCRC() {
					crcErrors++
					fmt.Fprintf(os.Stderr, "Warning: CRC mismatch at entry seq=%d in %s\n", e.Sequence, log.Name)
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
		totalEntries, totalWrites, totalTrims, len(logs))
	fmt.Printf("Output: %s (%s)\n", outputPath, fmtSize(deviceSize))
	fmt.Printf("CRC errors: %d\n", crcErrors)

	return nil
}

func replayToQCow2(logs []logSource, outputPath string, deviceSize uint64, blockSize uint32, incremental bool) error {
	var img *lbd.QCow2Image
	var err error

	if incremental {
		img, err = lbd.OpenQCow2(outputPath)
		if err != nil {
			return fmt.Errorf("opening qcow2 image for incremental replay: %w", err)
		}
	} else {
		img, err = lbd.CreateQCow2(outputPath, deviceSize, 16)
		if err != nil {
			return fmt.Errorf("creating qcow2 image: %w", err)
		}
	}

	var totalEntries, totalWrites, totalTrims, crcErrors int
	var totalBytes uint64

	for _, log := range logs {
		f, err := log.Open()
		if err != nil {
			img.Close()
			return fmt.Errorf("opening %s: %w", log.Name, err)
		}

		rd, err := lbd.NewReader(f)
		if err != nil {
			f.Close()
			img.Close()
			return fmt.Errorf("reading header from %s: %w", log.Name, err)
		}

		for {
			e, err := rd.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				img.Close()
				return fmt.Errorf("reading entry from %s: %w", log.Name, err)
			}

			totalEntries++
			offset := int64(e.Block) * int64(blockSize)

			if e.IsWrite() {
				if !e.ValidateCRC() {
					crcErrors++
					fmt.Fprintf(os.Stderr, "Warning: CRC mismatch at entry seq=%d in %s\n", e.Sequence, log.Name)
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
		totalEntries, totalWrites, totalTrims, len(logs))
	fmt.Printf("Output: %s (qcow2-lz4, virtual %s)\n", outputPath, fmtSize(deviceSize))
	fmt.Printf("CRC errors: %d\n", crcErrors)

	return nil
}

func tai64nLabel() string {
	return lbd.TAI64NLabel()
}

type repackArgs struct {
	Inplace    bool   `long:"inplace" usage:"write repacked file into log dir and remove old segments"`
	S3Bucket   string `long:"s3-bucket" usage:"S3 bucket containing log files"`
	S3Prefix   string `long:"s3-prefix" usage:"S3 key prefix"`
	S3Endpoint string `long:"s3-endpoint" usage:"S3-compatible endpoint URL"`
	S3Region   string `long:"s3-region" usage:"AWS region for S3"`
	VolName    string `long:"vol-name" usage:"volume name (required with --s3-bucket)"`
	LogDir     string `position:"0" usage:"directory containing log segment files"`
	OutputDir  string `position:"1" usage:"directory to write repacked log file"`
}

func runRepack(cfg *repackArgs) error {
	ctx := context.Background()

	var store lbd.LogStore
	if cfg.S3Bucket != "" {
		if cfg.VolName == "" {
			return fmt.Errorf("--vol-name is required with --s3-bucket")
		}
		u, err := lbd.NewS3Uploader(ctx, lbd.S3UploaderConfig{
			Bucket:   cfg.S3Bucket,
			Prefix:   cfg.S3Prefix,
			Endpoint: cfg.S3Endpoint,
			Region:   cfg.S3Region,
		})
		if err != nil {
			return fmt.Errorf("creating S3 client: %w", err)
		}
		store = lbd.NewS3LogStore(u, cfg.VolName)
	} else {
		if cfg.LogDir == "" {
			return fmt.Errorf("log directory or --s3-bucket is required")
		}
		if !cfg.Inplace && cfg.OutputDir == "" {
			return fmt.Errorf("output directory required (or use --inplace)")
		}
		store = &lbd.DirLogStore{Dir: cfg.LogDir}
	}

	// Step 1: Discover log files
	logFiles, err := store.List(ctx)
	if err != nil {
		return err
	}
	if len(logFiles) == 0 {
		return fmt.Errorf("no .log files found")
	}

	// Step 2: Read header from first file for device metadata
	firstRC, err := store.Open(ctx, logFiles[0])
	if err != nil {
		return fmt.Errorf("opening first log file: %w", err)
	}

	firstRd, err := lbd.NewReader(firstRC)
	if err != nil {
		firstRC.Close()
		return fmt.Errorf("reading header from %s: %w", logFiles[0], err)
	}

	label := tai64nLabel()

	outHdr := lbd.Header{
		Version:      firstRd.Header.Version,
		BlockSize:    firstRd.Header.BlockSize,
		SegmentLabel: label,
		DeviceSize:   firstRd.Header.DeviceSize,
		BackingPath:  firstRd.Header.BackingPath,
	}
	firstRC.Close()

	// Step 3: Read all entries, deduplicate via reverse BlockSet analysis,
	// and write only live portions to the output.
	var allEntries []*lbd.Entry
	var allNumBlocks []uint64

	for _, logID := range logFiles {
		rc, err := store.Open(ctx, logID)
		if err != nil {
			return fmt.Errorf("opening %s: %w", logID, err)
		}

		rd, err := lbd.NewReader(rc)
		if err != nil {
			rc.Close()
			return fmt.Errorf("reading header from %s: %w", logID, err)
		}

		for {
			e, err := rd.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				rc.Close()
				return fmt.Errorf("reading entry from %s: %w", logID, err)
			}

			numBlocks := uint64(e.Length) / uint64(outHdr.BlockSize)
			if numBlocks == 0 {
				numBlocks = 1
			}
			allEntries = append(allEntries, e)
			allNumBlocks = append(allNumBlocks, numBlocks)
		}

		rc.Close()
	}

	// Reverse BlockSet analysis: walk entries backwards to find which
	// block ranges in each entry are not shadowed by later entries.
	var covered lbd.BlockSet
	liveRanges := make([][]lbd.Interval, len(allEntries))
	for i := len(allEntries) - 1; i >= 0; i-- {
		lo := allEntries[i].Block
		hi := lo + allNumBlocks[i]
		uncovered := covered.Uncovered(lo, hi)
		liveRanges[i] = uncovered
		if len(uncovered) > 0 {
			covered.Add(lo, hi)
		}
	}

	// Write deduplicated entries to temp file.
	tmpFile, err := os.CreateTemp("", "lbd-repack-*.log.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	wr, err := lbd.NewWriter(tmpFile, outHdr)
	if err != nil {
		tmpFile.Close()
		return fmt.Errorf("writing output header: %w", err)
	}

	var totalEntries int
	var seq uint64
	blockSize := outHdr.BlockSize

	for i, e := range allEntries {
		for _, r := range liveRanges[i] {
			out := &lbd.Entry{
				Op:          e.Op,
				TimestampNS: e.TimestampNS,
				Sequence:    seq,
				Block:       r.Lo,
			}
			seq++

			if e.IsWrite() {
				dataStart := (r.Lo - e.Block) * uint64(blockSize)
				dataEnd := (r.Hi - e.Block) * uint64(blockSize)
				slice := e.Data[dataStart:dataEnd]
				out.Length = uint32(len(slice))
				out.Checksum = crc32.ChecksumIEEE(slice)
				out.Data = slice
			} else {
				out.Length = uint32((r.Hi - r.Lo) * uint64(blockSize))
			}

			if err := wr.WriteEntry(out); err != nil {
				tmpFile.Close()
				return fmt.Errorf("writing entry: %w", err)
			}
			totalEntries++
		}
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	// Step 4: Store the repacked file and optionally remove old segments
	if cfg.S3Bucket != "" {
		// S3 mode: always inplace (upload new, delete old)
		finalID := store.LogPath(label)
		if err := store.Put(ctx, finalID, tmpPath); err != nil {
			return fmt.Errorf("uploading repacked segment: %w", err)
		}

		for _, logID := range logFiles {
			if err := store.Delete(ctx, logID); err != nil {
				return fmt.Errorf("removing old segment %s: %w", logID, err)
			}
		}

		fmt.Printf("Repacked %d entries from %d files into %s\n", totalEntries, len(logFiles), finalID)
	} else {
		// Local mode
		outDir := cfg.OutputDir
		if cfg.Inplace {
			outDir = cfg.LogDir
		}

		finalPath := filepath.Join(outDir, "disk."+label+".log")
		if err := os.Rename(tmpPath, finalPath); err != nil {
			// Cross-filesystem: fall back to store.Put
			if err := store.Put(ctx, finalPath, tmpPath); err != nil {
				return fmt.Errorf("storing repacked segment: %w", err)
			}
		}

		if cfg.Inplace {
			for _, logID := range logFiles {
				if err := os.Remove(logID); err != nil {
					return fmt.Errorf("removing old segment %s: %w", logID, err)
				}
			}
		}

		fmt.Printf("Repacked %d entries from %d files into %s\n", totalEntries, len(logFiles), finalPath)
	}

	return nil
}

type scanArgs struct {
	DB         string `long:"db" usage:"path to SQLite hash database"`
	LogDir     string `long:"log-dir" usage:"directory to write log segment files"`
	DevicePath string `position:"0" usage:"block device or file to scan"`
}

func runScan(cfg *scanArgs) error {
	result, err := lbd.ScanDevice(lbd.ScanConfig{
		DBPath:     cfg.DB,
		LogDir:     cfg.LogDir,
		DevicePath: cfg.DevicePath,
	})
	if err != nil {
		return err
	}

	if result.LogPath == "" {
		fmt.Printf("Scanned %d runs (%s) — no changes detected\n",
			result.TotalRuns, fmtSize(uint64(result.DeviceSize)))
	} else {
		fmt.Printf("Scanned %d runs, %d changed, %d trimmed (%s written) → %s\n",
			result.TotalRuns, result.WriteCount, result.TrimCount,
			fmtSize(result.WriteBytes), result.LogPath)
	}
	return nil
}

type gcArgs struct {
	Threshold  int `long:"threshold" usage:"utilization threshold percentage (0-100) below which segments are retired" default:"50"`
	DryRun     bool    `long:"dry-run" usage:"show utilization without retiring segments"`
	LogDir     string  `position:"0" usage:"directory containing log segment files"`
	VolName    string  `long:"vol-name" usage:"volume name for S3 key prefix"`
	S3Bucket   string  `long:"s3-bucket" usage:"S3 bucket for log storage"`
	S3Prefix   string  `long:"s3-prefix" usage:"S3 key prefix"`
	S3Endpoint string  `long:"s3-endpoint" usage:"S3-compatible endpoint URL"`
	S3Region   string  `long:"s3-region" usage:"AWS region for S3"`
}

func runGC(cfg *gcArgs) error {
	gcCfg := lbd.GCConfig{
		Threshold: cfg.Threshold,
		DryRun:    cfg.DryRun,
	}

	if cfg.S3Bucket != "" {
		u, err := lbd.NewS3Uploader(context.Background(), lbd.S3UploaderConfig{
			Bucket:   cfg.S3Bucket,
			Prefix:   cfg.S3Prefix,
			Endpoint: cfg.S3Endpoint,
			Region:   cfg.S3Region,
		})
		if err != nil {
			return fmt.Errorf("creating S3 client: %w", err)
		}
		gcCfg.Store = lbd.NewS3LogStore(u, cfg.VolName)
	} else {
		if cfg.LogDir == "" {
			return fmt.Errorf("log directory or --s3-bucket is required")
		}
		gcCfg.LogDir = cfg.LogDir
	}

	result, err := lbd.RunGC(context.Background(), gcCfg)
	if err != nil {
		return err
	}

	// Print utilization table.
	fmt.Printf("%-40s %7s %5s %10s %10s %7s\n",
		"SEGMENT", "ENTRIES", "LIVE", "WRITE", "LIVE WRITE", "UTIL")
	fmt.Println(strings.Repeat("-", 86))

	retireSet := make(map[int]bool)
	for _, ri := range result.RetireIndexes {
		retireSet[ri] = true
	}

	for si, s := range result.Stats {
		name := filepath.Base(s.Path)
		util := s.Utilization()
		tag := ""
		if retireSet[si] {
			tag = " [RETIRE]"
		}
		fmt.Printf("%-40s %7d %5d %10s %10s %6.1f%%%s\n",
			name, s.TotalEntries, s.LiveEntries,
			fmtSize(s.TotalWriteBytes), fmtSize(s.LiveWriteBytes),
			util*100.0, tag)
	}
	fmt.Println()

	if len(result.RetireIndexes) == 0 {
		fmt.Printf("No segments below %d%% utilization threshold.\n", result.Threshold)
		return nil
	}

	fmt.Printf("%d segment(s) below %d%% utilization threshold.\n",
		len(result.RetireIndexes), result.Threshold)

	if cfg.DryRun {
		return nil
	}

	if result.CopiedEntries == 0 {
		fmt.Printf("Retired %d segment(s): no live entries to copy.\n", result.RetiredCount)
	} else {
		fmt.Printf("Retired %d segment(s): copied %d live entries (%s) into %s\n",
			result.RetiredCount, result.CopiedEntries, fmtSize(result.CopiedBytes),
			filepath.Base(result.NewSegmentPath))
	}

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
	if magic == lbd.QCow2Magic {
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
	img, err := lbd.OpenQCow2File(f)
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
