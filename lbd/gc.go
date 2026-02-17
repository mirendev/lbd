package lbd

import (
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
	LogDir    string  // directory containing log segment files
	Threshold float64 // utilization threshold (0.0-1.0); segments below this are retired
	DryRun    bool    // if true, analyze only without retiring
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
	Threshold      float64  // threshold used
	RetiredCount   int      // number of segments actually retired (0 if dry run)
	CopiedEntries  int      // entries copied to new segment
	CopiedBytes    uint64   // bytes copied
	NewSegmentPath string   // path to new segment; empty if none created
	DeletedPaths   []string // paths of deleted segment files
}

// entryMeta holds metadata for a single log entry during GC analysis.
type entryMeta struct {
	segIndex   int
	entryIndex int
	block      uint64
	numBlocks  uint64
	isWrite    bool
	dataLen    uint32
	liveRanges []Interval
}

type entryKey struct {
	segIndex, entryIndex int
}

// RunGC analyzes log segments for dead entries and optionally retires
// segments with utilization below the configured threshold.
func RunGC(cfg GCConfig) (*GCResult, error) {
	if cfg.LogDir == "" {
		return nil, fmt.Errorf("log directory is required")
	}

	threshold := cfg.Threshold
	if threshold == 0 {
		threshold = 0.5
	}

	logFiles, err := DiscoverLogFiles(cfg.LogDir)
	if err != nil {
		return nil, err
	}
	if len(logFiles) == 0 {
		return nil, fmt.Errorf("no .log files found in %s", cfg.LogDir)
	}

	// --- Pass 1: Analyze ---

	var allMeta []entryMeta
	stats := make([]SegmentStats, len(logFiles))

	var firstHeader Header

	for si, logPath := range logFiles {
		stats[si].Path = logPath

		f, err := os.Open(logPath)
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", logPath, err)
		}

		rd, err := NewReader(f)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("reading header from %s: %w", logPath, err)
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
				return nil, fmt.Errorf("reading entry from %s: %w", logPath, err)
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
				dataLen:    e.Length,
			}
			allMeta = append(allMeta, m)

			if e.IsWrite() {
				stats[si].TotalWriteBytes += uint64(e.Length)
			}
			stats[si].TotalEntries++

			ei++
		}

		f.Close()
	}

	// Process entries in reverse order (newest first) to determine liveness.
	var covered BlockSet
	blockSize := firstHeader.BlockSize
	for i := len(allMeta) - 1; i >= 0; i-- {
		m := &allMeta[i]
		lo := m.block
		hi := lo + m.numBlocks
		liveRanges := covered.Uncovered(lo, hi)
		m.liveRanges = liveRanges
		if len(liveRanges) > 0 {
			covered.Add(lo, hi)
		}
	}

	// Accumulate per-segment live stats.
	for i := range allMeta {
		m := &allMeta[i]
		if len(m.liveRanges) > 0 {
			stats[m.segIndex].LiveEntries++
			if m.isWrite {
				for _, r := range m.liveRanges {
					stats[m.segIndex].LiveWriteBytes += (r.Hi - r.Lo) * uint64(blockSize)
				}
			}
		}
	}

	result := &GCResult{
		Stats:     stats,
		Threshold: threshold,
	}

	// Identify segments to retire.
	for si, s := range stats {
		util := s.Utilization()
		if util < threshold && s.TotalWriteBytes > 0 {
			result.RetireIndexes = append(result.RetireIndexes, si)
		}
	}

	if len(result.RetireIndexes) == 0 || cfg.DryRun {
		return result, nil
	}

	// --- Pass 2: Retire ---

	// Build set of live entries in retired segments.
	liveSet := make(map[entryKey][]Interval)
	for i := range allMeta {
		m := &allMeta[i]
		if len(m.liveRanges) == 0 {
			continue
		}
		for _, ri := range result.RetireIndexes {
			if m.segIndex == ri {
				liveSet[entryKey{m.segIndex, m.entryIndex}] = m.liveRanges
				break
			}
		}
	}

	// If no live entries to copy, just delete the retired segments.
	if len(liveSet) == 0 {
		for _, ri := range result.RetireIndexes {
			if err := os.Remove(stats[ri].Path); err != nil {
				return nil, fmt.Errorf("removing %s: %w", stats[ri].Path, err)
			}
			result.DeletedPaths = append(result.DeletedPaths, stats[ri].Path)
		}
		result.RetiredCount = len(result.RetireIndexes)
		return result, nil
	}

	label := TAI64NLabel()
	tmpPath := filepath.Join(cfg.LogDir, "disk."+label+".log.tmp")
	finalPath := filepath.Join(cfg.LogDir, "disk."+label+".log")

	outFile, err := os.Create(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("creating output file: %w", err)
	}

	outHdr := Header{
		Version:      firstHeader.Version,
		BlockSize:    firstHeader.BlockSize,
		SegmentLabel: label,
		DeviceSize:   firstHeader.DeviceSize,
		BackingPath:  firstHeader.BackingPath,
	}

	wr, err := NewWriter(outFile, outHdr)
	if err != nil {
		outFile.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("writing output header: %w", err)
	}

	seq := uint64(0)

	for _, ri := range result.RetireIndexes {
		f, err := os.Open(stats[ri].Path)
		if err != nil {
			outFile.Close()
			os.Remove(tmpPath)
			return nil, fmt.Errorf("opening %s: %w", stats[ri].Path, err)
		}

		rd, err := NewReader(f)
		if err != nil {
			f.Close()
			outFile.Close()
			os.Remove(tmpPath)
			return nil, fmt.Errorf("reading header from %s: %w", stats[ri].Path, err)
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
				return nil, fmt.Errorf("reading entry from %s: %w", stats[ri].Path, err)
			}

			if ranges, ok := liveSet[entryKey{ri, ei}]; ok {
				for _, r := range ranges {
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
						f.Close()
						outFile.Close()
						os.Remove(tmpPath)
						return nil, fmt.Errorf("writing entry: %w", err)
					}
					result.CopiedEntries++
					if e.IsWrite() {
						result.CopiedBytes += uint64(splitEntry.Length)
					}
				}
			}

			ei++
		}

		f.Close()
	}

	if err := outFile.Close(); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("closing output file: %w", err)
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		return nil, fmt.Errorf("renaming temp file: %w", err)
	}

	result.NewSegmentPath = finalPath

	// Delete retired segments.
	for _, ri := range result.RetireIndexes {
		if err := os.Remove(stats[ri].Path); err != nil {
			return nil, fmt.Errorf("removing %s: %w", stats[ri].Path, err)
		}
		result.DeletedPaths = append(result.DeletedPaths, stats[ri].Path)
	}

	result.RetiredCount = len(result.RetireIndexes)
	return result, nil
}
