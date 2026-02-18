package lbd

import (
	"context"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Interval represents a half-open range [Lo, Hi) of block numbers.
type Interval struct {
	Lo, Hi uint64
}

// BlockSet tracks covered block ranges as sorted, non-overlapping, non-adjacent
// [Lo, Hi) intervals. Used to determine which blocks are shadowed by later entries.
type BlockSet struct {
	Intervals []Interval
}

// Add inserts the range [lo, hi) into the set, merging with any
// overlapping or adjacent existing intervals.
func (bs *BlockSet) Add(lo, hi uint64) {
	// Find all intervals that overlap or are adjacent to [lo, hi).
	first := -1
	last := -1
	for i, iv := range bs.Intervals {
		if iv.Lo <= hi && iv.Hi >= lo {
			if first == -1 {
				first = i
			}
			last = i
		}
	}

	if first == -1 {
		// No overlap — insert in sorted position.
		pos := sort.Search(len(bs.Intervals), func(i int) bool {
			return bs.Intervals[i].Lo >= lo
		})
		bs.Intervals = append(bs.Intervals, Interval{})
		copy(bs.Intervals[pos+1:], bs.Intervals[pos:])
		bs.Intervals[pos] = Interval{lo, hi}
		return
	}

	// Merge: expand to cover [lo, hi) and all overlapping intervals.
	merged := Interval{lo, hi}
	if bs.Intervals[first].Lo < merged.Lo {
		merged.Lo = bs.Intervals[first].Lo
	}
	if bs.Intervals[last].Hi > merged.Hi {
		merged.Hi = bs.Intervals[last].Hi
	}

	bs.Intervals[first] = merged
	if last > first {
		bs.Intervals = append(bs.Intervals[:first+1], bs.Intervals[last+1:]...)
	}
}

// Uncovered returns the sub-ranges of [lo, hi) NOT covered by any interval
// in the set.
func (bs *BlockSet) Uncovered(lo, hi uint64) []Interval {
	var gaps []Interval
	cursor := lo

	for _, iv := range bs.Intervals {
		if iv.Hi <= cursor {
			continue
		}
		if iv.Lo >= hi {
			break
		}
		if cursor < iv.Lo {
			gaps = append(gaps, Interval{cursor, iv.Lo})
		}
		if iv.Hi > cursor {
			cursor = iv.Hi
		}
	}

	if cursor < hi {
		gaps = append(gaps, Interval{cursor, hi})
	}
	return gaps
}

// CoversAll reports whether [lo, hi) is fully contained in a single interval.
func (bs *BlockSet) CoversAll(lo, hi uint64) bool {
	idx := sort.Search(len(bs.Intervals), func(i int) bool {
		return bs.Intervals[i].Hi > lo
	})
	if idx >= len(bs.Intervals) {
		return false
	}
	iv := bs.Intervals[idx]
	return iv.Lo <= lo && iv.Hi >= hi
}

// DiscoverLogFiles finds .log files in a directory, sorted by name.
// Files ending in .log.tmp are skipped.
func DiscoverLogFiles(dir string) ([]string, error) {
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

// GCConfig holds configuration for a GC run.
type GCConfig struct {
	LogDir    string   // directory containing log segment files (used when Store is nil)
	Store     LogStore // if non-nil, used instead of LogDir for all I/O
	Threshold int // utilization threshold as a percentage (0-100); segments below this are retired
	DryRun    bool     // if true, analyze only without retiring
}

// SegmentStats holds per-segment liveness statistics from GC analysis.
type SegmentStats struct {
	Path            string
	TotalWriteBytes uint64
	LiveWriteBytes  uint64
	TotalEntries    int
	LiveEntries     int
}

// Utilization returns the fraction of live write bytes to total write bytes.
// Returns 1.0 for segments with no write bytes (trim-only segments).
func (s *SegmentStats) Utilization() float64 {
	if s.TotalWriteBytes == 0 {
		return 1.0
	}
	return float64(s.LiveWriteBytes) / float64(s.TotalWriteBytes)
}

// GCResult holds the outcome of a GC run.
type GCResult struct {
	Stats          []SegmentStats
	RetireIndexes  []int    // indexes into Stats of segments below threshold
	Threshold      int      // threshold used (percentage)
	RetiredCount   int      // number of segments actually retired (0 if dry run)
	CopiedEntries  int      // entries copied to new segment
	CopiedBytes    uint64   // bytes copied
	NewSegmentPath string   // path to new segment; empty if none created
	DeletedPaths   []string // paths of deleted segment files
}

// RunGC analyzes log segments for dead entries and optionally retires
// segments with utilization below the configured threshold.
//
// If a LiveMap exists in the store, only new logs (those with labels after
// the map's last label) are processed. Otherwise all logs are analyzed.
// The updated LiveMap is saved after every run (including dry runs).
func RunGC(ctx context.Context, cfg GCConfig) (*GCResult, error) {
	store := cfg.Store
	if store == nil {
		if cfg.LogDir == "" {
			return nil, fmt.Errorf("log directory or store is required")
		}
		store = &DirLogStore{Dir: cfg.LogDir}
	}

	threshold := cfg.Threshold

	logFiles, err := store.List(ctx)
	if err != nil {
		return nil, err
	}
	if len(logFiles) == 0 {
		return nil, fmt.Errorf("no .log files found")
	}

	// Load or create LiveMap.
	lm, err := LoadLiveMap(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("loading live map: %w", err)
	}

	var logsToProcess []string
	if lm != nil {
		// Incremental: only process logs newer than the last saved label.
		for _, logID := range logFiles {
			label := LabelFromLogPath(logID)
			if label > lm.LastLabel {
				logsToProcess = append(logsToProcess, logID)
			}
		}
		// Clean up segments that no longer exist in the store.
		existingLogs := make(map[string]bool, len(logFiles))
		for _, logID := range logFiles {
			existingLogs[logID] = true
		}
		for segID := range lm.Segments {
			if !existingLogs[segID] {
				lm.RemoveSegment(segID)
			}
		}
	} else {
		logsToProcess = logFiles
	}

	// Read first header for device metadata (needed for retirement output).
	rc, err := store.Open(ctx, logFiles[0])
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", logFiles[0], err)
	}
	firstRd, err := NewReader(rc)
	if err != nil {
		rc.Close()
		return nil, fmt.Errorf("reading header from %s: %w", logFiles[0], err)
	}
	firstHeader := firstRd.Header
	rc.Close()

	if lm == nil {
		lm = NewLiveMap(firstHeader.BlockSize)
	}

	// Process new logs through the LiveMap.
	for _, logID := range logsToProcess {
		rc, err := store.Open(ctx, logID)
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", logID, err)
		}

		rd, err := NewReader(rc)
		if err != nil {
			rc.Close()
			return nil, fmt.Errorf("reading header from %s: %w", logID, err)
		}

		for {
			e, err := rd.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				rc.Close()
				return nil, fmt.Errorf("reading entry from %s: %w", logID, err)
			}

			numBlocks := uint64(e.Length) / uint64(rd.Header.BlockSize)
			if numBlocks == 0 {
				numBlocks = 1
			}

			if e.IsWrite() {
				lm.ApplyWrite(e.Block, numBlocks, logID)
				lm.AddSegmentEntry(logID, true, uint64(e.Length))
			} else if e.IsTrim() {
				lm.ApplyTrim(e.Block, numBlocks, logID)
				lm.AddSegmentEntry(logID, false, 0)
			}
		}

		lm.LastLabel = LabelFromLogPath(logID)
		rc.Close()
	}

	// Compute stats from the LiveMap.
	stats := lm.ComputeStats()

	result := &GCResult{
		Stats:     stats,
		Threshold: threshold,
	}

	// Identify segments to retire. When there are multiple segments, the
	// most recent one (last in sorted order) is excluded from retirement
	// because it may have been created by a previous GC run and retiring
	// it would cause an endless retire-recreate cycle.
	thresholdFrac := float64(threshold) / 100.0
	lastIdx := len(stats) - 1
	for si, s := range stats {
		if si == lastIdx && len(stats) > 1 {
			continue
		}
		util := s.Utilization()
		if util < thresholdFrac && s.TotalWriteBytes > 0 {
			result.RetireIndexes = append(result.RetireIndexes, si)
		}
	}

	if len(result.RetireIndexes) == 0 || cfg.DryRun {
		if err := SaveLiveMap(ctx, store, lm); err != nil {
			return nil, fmt.Errorf("saving live map: %w", err)
		}
		return result, nil
	}

	// --- Retire ---

	// Check whether any retired segments have live extents.
	hasLive := false
	for _, ri := range result.RetireIndexes {
		if len(lm.SegmentLiveExtents(stats[ri].Path)) > 0 {
			hasLive = true
			break
		}
	}

	if !hasLive {
		// No live data — just delete retired segments.
		for _, ri := range result.RetireIndexes {
			if err := store.Delete(ctx, stats[ri].Path); err != nil {
				return nil, fmt.Errorf("removing %s: %w", stats[ri].Path, err)
			}
			result.DeletedPaths = append(result.DeletedPaths, stats[ri].Path)
			lm.RemoveSegment(stats[ri].Path)
		}
		result.RetiredCount = len(result.RetireIndexes)
		if err := SaveLiveMap(ctx, store, lm); err != nil {
			return nil, fmt.Errorf("saving live map: %w", err)
		}
		return result, nil
	}

	// Create new compacted segment from live entries in retired segments.
	label := TAI64NLabel()
	blockSize := firstHeader.BlockSize

	tmpFile, err := os.CreateTemp("", "lbd-gc-*.log.tmp")
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	outHdr := Header{
		Version:      firstHeader.Version,
		BlockSize:    blockSize,
		SegmentLabel: label,
		DeviceSize:   firstHeader.DeviceSize,
		BackingPath:  firstHeader.BackingPath,
	}

	wr, err := NewWriter(tmpFile, outHdr)
	if err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("writing output header: %w", err)
	}

	seq := uint64(0)

	for _, ri := range result.RetireIndexes {
		segPath := stats[ri].Path
		segExtents := lm.SegmentLiveExtents(segPath)
		if len(segExtents) == 0 {
			continue
		}

		// Read segment entries and determine within-segment liveness
		// via reverse BlockSet analysis, then intersect with the LiveMap
		// extents to account for cross-segment supersession.
		entries, numBlocksList, err := readSegmentEntries(ctx, store, segPath, blockSize)
		if err != nil {
			tmpFile.Close()
			return nil, err
		}

		entryLiveRanges := computeRetireLiveness(entries, numBlocksList, segExtents)

		for i, e := range entries {
			for _, r := range entryLiveRanges[i] {
				splitEntry := &Entry{
					Op:          e.Op,
					TimestampNS: uint64(time.Now().UnixNano()),
					Sequence:    seq,
					Block:       r.Lo,
				}
				seq++
				if e.IsWrite() {
					dataStart := (r.Lo - e.Block) * uint64(blockSize)
					dataEnd := (r.Hi - e.Block) * uint64(blockSize)
					slice := e.Data[dataStart:dataEnd]
					splitEntry.Length = uint32(len(slice))
					splitEntry.Checksum = crc32.ChecksumIEEE(slice)
					splitEntry.Data = slice
				} else {
					splitEntry.Length = uint32((r.Hi - r.Lo) * uint64(blockSize))
				}
				if err := wr.WriteEntry(splitEntry); err != nil {
					tmpFile.Close()
					return nil, fmt.Errorf("writing entry: %w", err)
				}
				result.CopiedEntries++
				if e.IsWrite() {
					result.CopiedBytes += uint64(splitEntry.Length)
				}
			}
		}
	}

	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("closing output file: %w", err)
	}

	finalID := store.LogPath(label)
	if err := store.Put(ctx, finalID, tmpPath); err != nil {
		return nil, fmt.Errorf("storing new segment: %w", err)
	}

	result.NewSegmentPath = finalID

	// Delete retired segments and update LiveMap.
	for _, ri := range result.RetireIndexes {
		if err := store.Delete(ctx, stats[ri].Path); err != nil {
			return nil, fmt.Errorf("removing %s: %w", stats[ri].Path, err)
		}
		result.DeletedPaths = append(result.DeletedPaths, stats[ri].Path)
		lm.ReattributeSegment(stats[ri].Path, finalID)
		delete(lm.Segments, stats[ri].Path)
	}
	lm.Segments[finalID] = &SegInfo{
		TotalEntries:    result.CopiedEntries,
		TotalWriteBytes: result.CopiedBytes,
	}

	result.RetiredCount = len(result.RetireIndexes)

	if err := SaveLiveMap(ctx, store, lm); err != nil {
		return nil, fmt.Errorf("saving live map: %w", err)
	}

	return result, nil
}

// readSegmentEntries reads all entries from a segment.
func readSegmentEntries(ctx context.Context, store LogStore, segPath string, blockSize uint32) ([]*Entry, []uint64, error) {
	rc, err := store.Open(ctx, segPath)
	if err != nil {
		return nil, nil, fmt.Errorf("opening %s: %w", segPath, err)
	}
	defer rc.Close()

	rd, err := NewReader(rc)
	if err != nil {
		return nil, nil, fmt.Errorf("reading header from %s: %w", segPath, err)
	}

	var entries []*Entry
	var numBlocksList []uint64
	for {
		e, err := rd.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("reading entry from %s: %w", segPath, err)
		}
		numBlocks := uint64(e.Length) / uint64(blockSize)
		if numBlocks == 0 {
			numBlocks = 1
		}
		entries = append(entries, e)
		numBlocksList = append(numBlocksList, numBlocks)
	}
	return entries, numBlocksList, nil
}

// computeRetireLiveness determines per-entry live ranges for a retired segment.
// It uses reverse BlockSet analysis for within-segment liveness, then
// intersects with the LiveMap's segment extents for cross-segment filtering.
func computeRetireLiveness(entries []*Entry, numBlocksList []uint64, segExtents []LiveExtent) [][]Interval {
	// Reverse analysis for within-segment liveness.
	var covered BlockSet
	withinLive := make([][]Interval, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		lo := entries[i].Block
		hi := lo + numBlocksList[i]
		uncovered := covered.Uncovered(lo, hi)
		withinLive[i] = uncovered
		if len(uncovered) > 0 {
			covered.Add(lo, hi)
		}
	}

	// Intersect within-segment liveness with LiveMap segment extents.
	result := make([][]Interval, len(entries))
	for i := range entries {
		for _, r := range withinLive[i] {
			result[i] = append(result[i], intersectRange(segExtents, r.Lo, r.Hi)...)
		}
	}
	return result
}
