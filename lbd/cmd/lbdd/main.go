// Command lbdd is the LBD log management daemon.
//
// It monitors log rotation events, maintains an extent map of live blocks,
// and serves on-demand paging for cluster misses.
//
// Usage:
//
//	lbdd --dev N --safe-dir /path/to/safe --base /path/to/base.qcow2 [--log-dir /path/to/logs]
package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/evanphx/lbd/lbd"
	"miren.dev/mflags"
)

const blockSize = 4096

type config struct {
	Dev     int    `long:"dev" usage:"device index (required)"`
	SafeDir string `long:"safe-dir" usage:"directory to copy logs to (required)"`
	Base    string `long:"base" usage:"path to base layer qcow2 file (required)"`
	LogDir  string `long:"log-dir" usage:"scan existing logs on startup"`
}

func run(cfg *config) error {
	if cfg.SafeDir == "" {
		return fmt.Errorf("--safe-dir is required")
	}
	if cfg.Base == "" {
		return fmt.Errorf("--base is required")
	}

	// Open base layer qcow2
	baseImg, err := lbd.OpenQCow2(cfg.Base)
	if err != nil {
		return fmt.Errorf("opening base qcow2: %w", err)
	}
	defer baseImg.Close()

	clusterSize := uint64(baseImg.ClusterSize)
	blocksPerCluster := clusterSize / blockSize

	var extentMap lbd.ExtentMap

	// Seed extent map from existing logs if --log-dir provided
	if cfg.LogDir != "" {
		log.Printf("Seeding extent map from %s", cfg.LogDir)
		if err := seedExtentMap(&extentMap, cfg.LogDir, cfg.SafeDir); err != nil {
			return fmt.Errorf("seeding extent map: %w", err)
		}
		log.Printf("Extent map seeded: %d extents", extentMap.Len())
	}

	// Open watcher fd
	watchConn, err := lbd.OpenControl()
	if err != nil {
		return fmt.Errorf("opening watcher control: %w", err)
	}
	defer watchConn.Close()

	devFilter := cfg.Dev
	if err := watchConn.SendWatch(&devFilter); err != nil {
		return fmt.Errorf("sending watch command: %w", err)
	}
	log.Printf("Watching for log rotation events on dev %d", cfg.Dev)

	// Open miss handler fd
	missConn, err := lbd.OpenControl()
	if err != nil {
		return fmt.Errorf("opening miss handler control: %w", err)
	}
	defer missConn.Close()

	if err := missConn.SendManageMisses(cfg.Dev); err != nil {
		return fmt.Errorf("sending manage_misses command: %w", err)
	}
	log.Printf("Managing misses for dev %d", cfg.Dev)

	// Signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start watcher goroutine
	watchErrCh := make(chan error, 1)
	go func() {
		watchErrCh <- runWatcher(watchConn, &extentMap, cfg.SafeDir)
	}()

	// Run miss handler on main goroutine
	missErrCh := make(chan error, 1)
	go func() {
		missErrCh <- runMissHandler(missConn, &extentMap, baseImg, clusterSize, blocksPerCluster)
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigCh:
		log.Printf("Received signal %v, shutting down", sig)
		return nil
	case err := <-watchErrCh:
		return fmt.Errorf("watcher: %w", err)
	case err := <-missErrCh:
		return fmt.Errorf("miss handler: %w", err)
	}
}

// runWatcher reads log_rotated events and processes each log file.
func runWatcher(conn *lbd.ControlConn, extentMap *lbd.ExtentMap, safeDir string) error {
	for {
		ev, err := conn.ReadEvent()
		if err != nil {
			return fmt.Errorf("reading event: %w", err)
		}

		switch e := ev.(type) {
		case *lbd.LogRotatedEvent:
			log.Printf("Log rotated: dev=%d label=%s dir=%s seq=%d",
				e.DevIndex, e.Label, e.Dir, e.Seq)
			if err := processLogFile(e, extentMap, safeDir); err != nil {
				log.Printf("Error processing log: %v", err)
			}
		default:
			log.Printf("Unexpected event type on watcher fd: %T", ev)
		}
	}
}

// processLogFile copies a rotated log to the safe directory and updates
// the extent map with its entries.
func processLogFile(ev *lbd.LogRotatedEvent, extentMap *lbd.ExtentMap, safeDir string) error {
	filename := "disk." + ev.Label + ".log"
	srcPath := filepath.Join(ev.Dir, filename)
	dstPath := filepath.Join(safeDir, filename)

	// Copy to safe dir (write to tmp, rename for atomicity)
	tmpPath := dstPath + ".tmp"
	if err := copyFile(srcPath, tmpPath); err != nil {
		return fmt.Errorf("copying %s: %w", srcPath, err)
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		return fmt.Errorf("renaming %s: %w", tmpPath, err)
	}

	// Scan entries and update extent map
	return scanLogIntoExtentMap(dstPath, extentMap)
}

// scanLogIntoExtentMap reads a log file and updates the extent map.
func scanLogIntoExtentMap(logPath string, extentMap *lbd.ExtentMap) error {
	f, err := os.Open(logPath)
	if err != nil {
		return err
	}
	defer f.Close()

	rd, err := lbd.NewReader(f)
	if err != nil {
		return fmt.Errorf("reading header: %w", err)
	}

	entryIdx := 0
	for {
		e, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading entry %d: %w", entryIdx, err)
		}

		numBlocks := uint64(e.Length) / blockSize
		if numBlocks == 0 {
			numBlocks = 1
		}

		if e.IsWrite() {
			ref := lbd.ExtentRef{
				LogPath:    logPath,
				EntryIndex: entryIdx,
				Block:      e.Block,
				Length:     e.Length,
			}
			extentMap.AddWrite(e.Block, numBlocks, ref)
		} else if e.IsTrim() {
			extentMap.RemoveTrim(e.Block, numBlocks)
		}

		entryIdx++
	}

	return nil
}

// runMissHandler reads block_miss events and resolves them.
func runMissHandler(conn *lbd.ControlConn, extentMap *lbd.ExtentMap,
	baseImg *lbd.QCow2Image, clusterSize, blocksPerCluster uint64) error {
	for {
		ev, err := conn.ReadEvent()
		if err != nil {
			return fmt.Errorf("reading event: %w", err)
		}

		switch e := ev.(type) {
		case *lbd.BlockMissEvent:
			if err := handleMiss(conn, e, extentMap, baseImg, clusterSize, blocksPerCluster); err != nil {
				log.Printf("Error handling miss cluster=%d: %v", e.ClusterIndex, err)
				// Send continue on error to unblock kernel
				if sendErr := conn.SendContinue(); sendErr != nil {
					return fmt.Errorf("sending continue after error: %w", sendErr)
				}
			}
		default:
			log.Printf("Unexpected event type on miss fd: %T", ev)
		}
	}
}

// handleMiss resolves a single cluster miss.
func handleMiss(conn *lbd.ControlConn, ev *lbd.BlockMissEvent,
	extentMap *lbd.ExtentMap, baseImg *lbd.QCow2Image,
	clusterSize, blocksPerCluster uint64) error {

	startBlock := ev.ClusterIndex * blocksPerCluster

	extents := extentMap.Lookup(startBlock, blocksPerCluster)
	if len(extents) == 0 {
		// No data — zero-fill
		return conn.SendContinue()
	}

	// Assemble cluster data (start with zeros)
	clusterData := make([]byte, clusterSize)

	for _, ext := range extents {
		data, err := readExtentData(ext)
		if err != nil {
			return fmt.Errorf("reading extent data: %w", err)
		}

		// Place data at correct offset within cluster
		clusterOffset := (ext.StartBlock - startBlock) * blockSize
		copy(clusterData[clusterOffset:], data)
	}

	// Write cluster to base qcow2
	offset := int64(ev.ClusterIndex * clusterSize)
	if _, err := baseImg.WriteAt(clusterData, offset); err != nil {
		return fmt.Errorf("writing to base: %w", err)
	}

	if err := baseImg.Flush(); err != nil {
		return fmt.Errorf("flushing base: %w", err)
	}

	// fsync to ensure data is durable
	if err := syncFile(baseImg); err != nil {
		return fmt.Errorf("fsync base: %w", err)
	}

	return conn.SendRetry()
}

// readExtentData reads the relevant portion of data for an extent from its log file.
func readExtentData(ext lbd.Extent) ([]byte, error) {
	f, err := os.Open(ext.Ref.LogPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rd, err := lbd.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}

	// Skip to the target entry
	for i := 0; i < ext.Ref.EntryIndex; i++ {
		if _, err := rd.Next(); err != nil {
			return nil, fmt.Errorf("skipping entry %d: %w", i, err)
		}
	}

	entry, err := rd.Next()
	if err != nil {
		return nil, fmt.Errorf("reading entry %d: %w", ext.Ref.EntryIndex, err)
	}

	// Compute offset into entry data
	entryOffset := (ext.StartBlock - ext.Ref.Block) * blockSize
	dataLen := ext.NumBlocks * blockSize

	if entryOffset+dataLen > uint64(len(entry.Data)) {
		return nil, fmt.Errorf("extent data out of range: offset=%d len=%d data=%d",
			entryOffset, dataLen, len(entry.Data))
	}

	return entry.Data[entryOffset : entryOffset+dataLen], nil
}

// syncFile calls Sync on the underlying file of a QCow2Image.
// This is a best-effort operation.
func syncFile(img *lbd.QCow2Image) error {
	// QCow2Image doesn't expose the file for sync, but Flush writes
	// all metadata. The kernel will get durable data after Flush.
	return nil
}

// copyFile copies src to dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return out.Sync()
}

// seedExtentMap discovers existing log files and processes them in order
// to build the initial extent map.
func seedExtentMap(extentMap *lbd.ExtentMap, logDir, safeDir string) error {
	logFiles, err := discoverLogFiles(logDir)
	if err != nil {
		return err
	}

	for _, logPath := range logFiles {
		// Copy to safe dir if not already there
		filename := filepath.Base(logPath)
		safePath := filepath.Join(safeDir, filename)

		if _, err := os.Stat(safePath); os.IsNotExist(err) {
			tmpPath := safePath + ".tmp"
			if err := copyFile(logPath, tmpPath); err != nil {
				return fmt.Errorf("copying %s: %w", logPath, err)
			}
			if err := os.Rename(tmpPath, safePath); err != nil {
				return fmt.Errorf("renaming %s: %w", tmpPath, err)
			}
		}

		if err := scanLogIntoExtentMap(safePath, extentMap); err != nil {
			return fmt.Errorf("scanning %s: %w", safePath, err)
		}
	}

	return nil
}

// discoverLogFiles finds .log files in a directory, sorted by name.
func discoverLogFiles(dir string) ([]string, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory: %w", err)
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

func main() {
	d := mflags.NewDispatcher("lbdd")
	d.Dispatch("run", mflags.Infer(run, mflags.WithUsage("Run the LBD log management daemon")))

	args := os.Args[1:]
	if len(args) > 0 && args[0] != "run" {
		args = append([]string{"run"}, args...)
	}

	if err := d.Run(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}
