package main

import (
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/evanphx/lbd/lbdlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- blockSet unit tests ---

func TestBlockSetAddDisjoint(t *testing.T) {
	var bs blockSet

	bs.add(10, 20)
	bs.add(30, 40)
	bs.add(50, 60)

	require.Len(t, bs.intervals, 3)
	assert.Equal(t, interval{10, 20}, bs.intervals[0])
	assert.Equal(t, interval{30, 40}, bs.intervals[1])
	assert.Equal(t, interval{50, 60}, bs.intervals[2])
}

func TestBlockSetAddOverlapping(t *testing.T) {
	var bs blockSet

	bs.add(10, 20)
	bs.add(15, 30)

	require.Len(t, bs.intervals, 1)
	assert.Equal(t, interval{10, 30}, bs.intervals[0])
}

func TestBlockSetAddAdjacent(t *testing.T) {
	var bs blockSet

	bs.add(10, 20)
	bs.add(20, 30)

	require.Len(t, bs.intervals, 1)
	assert.Equal(t, interval{10, 30}, bs.intervals[0])
}

func TestBlockSetAddMergesMultiple(t *testing.T) {
	var bs blockSet

	bs.add(0, 10)
	bs.add(20, 30)
	bs.add(40, 50)

	require.Len(t, bs.intervals, 3)

	// Bridge the gap between all three.
	bs.add(5, 45)

	require.Len(t, bs.intervals, 1)
	assert.Equal(t, interval{0, 50}, bs.intervals[0])
}

func TestBlockSetAddInsertionOrder(t *testing.T) {
	// Add in reverse order — should still be sorted.
	var bs blockSet

	bs.add(50, 60)
	bs.add(30, 40)
	bs.add(10, 20)

	require.Len(t, bs.intervals, 3)
	assert.Equal(t, interval{10, 20}, bs.intervals[0])
	assert.Equal(t, interval{30, 40}, bs.intervals[1])
	assert.Equal(t, interval{50, 60}, bs.intervals[2])
}

func TestBlockSetAddSuperset(t *testing.T) {
	var bs blockSet

	bs.add(10, 20)
	bs.add(5, 25) // superset of existing

	require.Len(t, bs.intervals, 1)
	assert.Equal(t, interval{5, 25}, bs.intervals[0])
}

func TestBlockSetAddSubset(t *testing.T) {
	var bs blockSet

	bs.add(5, 25)
	bs.add(10, 20) // subset of existing

	require.Len(t, bs.intervals, 1)
	assert.Equal(t, interval{5, 25}, bs.intervals[0])
}

func TestBlockSetCoversAllEmpty(t *testing.T) {
	var bs blockSet
	assert.False(t, bs.coversAll(0, 10))
}

func TestBlockSetCoversAllExactMatch(t *testing.T) {
	var bs blockSet
	bs.add(10, 20)
	assert.True(t, bs.coversAll(10, 20))
}

func TestBlockSetCoversAllSubrange(t *testing.T) {
	var bs blockSet
	bs.add(0, 100)
	assert.True(t, bs.coversAll(10, 20))
	assert.True(t, bs.coversAll(0, 1))
	assert.True(t, bs.coversAll(99, 100))
}

func TestBlockSetCoversAllPartiallyUncovered(t *testing.T) {
	var bs blockSet
	bs.add(10, 20)

	assert.False(t, bs.coversAll(5, 15))  // extends below
	assert.False(t, bs.coversAll(15, 25)) // extends above
	assert.False(t, bs.coversAll(5, 25))  // extends both
}

func TestBlockSetCoversAllGap(t *testing.T) {
	var bs blockSet
	bs.add(0, 10)
	bs.add(20, 30)

	// The range [5, 25) spans a gap — should not be covered.
	assert.False(t, bs.coversAll(5, 25))
	// Each piece individually is covered.
	assert.True(t, bs.coversAll(0, 10))
	assert.True(t, bs.coversAll(20, 30))
}

func TestBlockSetCoversAllDisjointRange(t *testing.T) {
	var bs blockSet
	bs.add(0, 10)

	assert.False(t, bs.coversAll(50, 60))
}

// --- blockSet.uncovered unit tests ---

func TestBlockSetUncoveredEmpty(t *testing.T) {
	var bs blockSet
	gaps := bs.uncovered(0, 10)
	assert.Equal(t, []interval{{0, 10}}, gaps)
}

func TestBlockSetUncoveredFullyCovered(t *testing.T) {
	var bs blockSet
	bs.add(0, 10)
	gaps := bs.uncovered(0, 10)
	assert.Empty(t, gaps)
}

func TestBlockSetUncoveredSupersetCovered(t *testing.T) {
	var bs blockSet
	bs.add(0, 20)
	gaps := bs.uncovered(5, 15)
	assert.Empty(t, gaps)
}

func TestBlockSetUncoveredGapInMiddle(t *testing.T) {
	var bs blockSet
	bs.add(0, 3)
	bs.add(7, 10)
	gaps := bs.uncovered(0, 10)
	assert.Equal(t, []interval{{3, 7}}, gaps)
}

func TestBlockSetUncoveredLeadingGap(t *testing.T) {
	var bs blockSet
	bs.add(5, 10)
	gaps := bs.uncovered(0, 10)
	assert.Equal(t, []interval{{0, 5}}, gaps)
}

func TestBlockSetUncoveredTrailingGap(t *testing.T) {
	var bs blockSet
	bs.add(0, 5)
	gaps := bs.uncovered(0, 10)
	assert.Equal(t, []interval{{5, 10}}, gaps)
}

func TestBlockSetUncoveredMultipleGaps(t *testing.T) {
	var bs blockSet
	bs.add(2, 4)
	bs.add(6, 8)
	gaps := bs.uncovered(0, 10)
	assert.Equal(t, []interval{{0, 2}, {4, 6}, {8, 10}}, gaps)
}

func TestBlockSetUncoveredPartialOverlap(t *testing.T) {
	// Covered interval extends beyond the query range.
	var bs blockSet
	bs.add(5, 20)
	gaps := bs.uncovered(0, 10)
	assert.Equal(t, []interval{{0, 5}}, gaps)
}

func TestBlockSetUncoveredNoOverlap(t *testing.T) {
	var bs blockSet
	bs.add(20, 30)
	gaps := bs.uncovered(0, 10)
	assert.Equal(t, []interval{{0, 10}}, gaps)
}

// --- Helpers for GC integration tests ---

const testBlockSize = 4096

func testHeader(label string) lbdlog.Header {
	return lbdlog.Header{
		Version:      2,
		BlockSize:    testBlockSize,
		SegmentLabel: label,
		DeviceSize:   1024 * 1024,
		BackingPath:  "/tmp/test.img",
	}
}

func writeSegment(t *testing.T, dir, name string, hdr lbdlog.Header, entries []*lbdlog.Entry) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	wr, err := lbdlog.NewWriter(f, hdr)
	require.NoError(t, err)

	for _, e := range entries {
		require.NoError(t, wr.WriteEntry(e))
	}
	return path
}

func makeWriteEntry(block uint64, numBlocks int, seq uint64, fill byte) *lbdlog.Entry {
	data := make([]byte, numBlocks*testBlockSize)
	for i := range data {
		data[i] = fill
	}
	return &lbdlog.Entry{
		Op:       "W",
		Sequence: seq,
		Block:    block,
		Length:   uint32(len(data)),
		Checksum: crc32.ChecksumIEEE(data),
		Data:     data,
	}
}

func makeTrimEntry(block uint64, numBlocks int, seq uint64) *lbdlog.Entry {
	return &lbdlog.Entry{
		Op:       "T",
		Sequence: seq,
		Block:    block,
		Length:   uint32(numBlocks * testBlockSize),
	}
}

func readAllEntries(t *testing.T, path string) []*lbdlog.Entry {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	rd, err := lbdlog.NewReader(f)
	require.NoError(t, err)

	var entries []*lbdlog.Entry
	for {
		e, err := rd.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		entries = append(entries, e)
	}
	return entries
}

func logFilesInDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	var files []string
	for _, de := range entries {
		if !de.IsDir() && filepath.Ext(de.Name()) == ".log" {
			files = append(files, filepath.Join(dir, de.Name()))
		}
	}
	sort.Strings(files)
	return files
}

// --- GC integration tests ---

func TestGCNoShadowing(t *testing.T) {
	// Two segments, no overlapping blocks → everything is live, nothing retired.
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbdlog.Entry{
		makeWriteEntry(10, 1, 0, 'B'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.5})
	require.NoError(t, err)

	// Both originals should still exist — nothing retired.
	files := logFilesInDir(t, dir)
	assert.Len(t, files, 2)
}

func TestGCFullShadow(t *testing.T) {
	// Segment 1 writes to block 0. Segment 2 writes to block 0 again.
	// Segment 1 is 0% utilized → retired.
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'B'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.5})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	// Original segment 1 deleted, segment 2 untouched, no new segment (0 live entries).
	require.Len(t, files, 1)
	assert.Contains(t, filepath.Base(files[0]), "bbb")

	// The surviving segment should have the 'B' write.
	entries := readAllEntries(t, files[0])
	require.Len(t, entries, 1)
	assert.Equal(t, byte('B'), entries[0].Data[0])
}

func TestGCPartialShadow(t *testing.T) {
	// Segment 1 writes to blocks 0 and 5.
	// Segment 2 writes to block 0 only.
	// Block 0 in seg1 is dead, block 5 is live → seg1 util = 50%.
	// With threshold 0.6 → retired; live entry (block 5) copied to new segment.
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
		makeWriteEntry(5, 1, 1, 'C'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'B'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.6})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	// seg1 retired → deleted, new segment created with live entry.
	// seg2 untouched. So 2 files total.
	require.Len(t, files, 2)

	// Find the new segment (not bbb).
	var newSegPath string
	for _, f := range files {
		if filepath.Base(f) != "disk.bbb.log" {
			newSegPath = f
		}
	}
	require.NotEmpty(t, newSegPath, "expected new segment file")

	// New segment should have a fresh label (sorts after bbb).
	assert.NotContains(t, filepath.Base(newSegPath), "aaa",
		"new segment should have a fresh label")

	// New segment should have exactly a 1-block entry for block 5 (fill 'C').
	entries := readAllEntries(t, newSegPath)
	require.Len(t, entries, 1)
	assert.Equal(t, uint64(5), entries[0].Block)
	assert.Equal(t, uint32(testBlockSize), entries[0].Length)
	assert.Equal(t, byte('C'), entries[0].Data[0])
	assert.True(t, entries[0].ValidateCRC())
}

func TestGCDryRunDoesNotModify(t *testing.T) {
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'B'),
	})

	filesBefore := logFilesInDir(t, dir)

	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.5, DryRun: true})
	require.NoError(t, err)

	filesAfter := logFilesInDir(t, dir)
	assert.Equal(t, filesBefore, filesAfter, "dry-run should not change files")
}

func TestGCTrimShadowsWrite(t *testing.T) {
	// Segment 1 writes to block 0.
	// Segment 2 trims block 0.
	// Segment 1's write is dead.
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbdlog.Entry{
		makeTrimEntry(0, 1, 0),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.5})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	// Seg1 retired (0% util), no live entries → no new segment.
	// Seg2 is trim-only (util=1.0) → kept.
	require.Len(t, files, 1)
	assert.Contains(t, filepath.Base(files[0]), "bbb")
}

func TestGCTrimOnlySegmentKept(t *testing.T) {
	// A segment with only trims has totalWriteBytes=0, util=1.0 → never retired.
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeTrimEntry(0, 10, 0),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.5})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 1)
	assert.Contains(t, filepath.Base(files[0]), "aaa")
}

func TestGCMultiBlockShadowing(t *testing.T) {
	// Segment 1 writes 4 blocks starting at block 0.
	// Segment 2 writes 2 blocks at block 0 and 2 blocks at block 2.
	// This fully shadows seg1's 4-block write.
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeWriteEntry(0, 4, 0, 'A'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbdlog.Entry{
		makeWriteEntry(0, 2, 0, 'B'),
		makeWriteEntry(2, 2, 1, 'C'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.5})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	// Seg1 fully dead → retired, no live entries → no new segment.
	require.Len(t, files, 1)
	assert.Contains(t, filepath.Base(files[0]), "bbb")
}

func TestGCWithinSegmentShadowing(t *testing.T) {
	// A single segment where the second entry shadows the first.
	// Both entries in the same segment: the later one wins.
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
		makeWriteEntry(0, 1, 1, 'B'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.5})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	// util = 50% (4096 live out of 8192 total) → exactly at threshold, not retired.
	// With threshold 0.5, util < 0.5 triggers retire, but 0.5 == 0.5 doesn't.
	require.Len(t, files, 1)
	assert.Contains(t, filepath.Base(files[0]), "aaa")
}

func TestGCWithinSegmentShadowingRetired(t *testing.T) {
	// Same as above but with a higher threshold so it gets retired.
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
		makeWriteEntry(0, 1, 1, 'B'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.6})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	// Retired and replaced with a new segment (fresh label, not "aaa").
	require.Len(t, files, 1)
	assert.NotContains(t, filepath.Base(files[0]), "aaa",
		"new segment should have a fresh label, not reuse the retired label")

	entries := readAllEntries(t, files[0])
	require.Len(t, entries, 1)
	assert.Equal(t, uint64(0), entries[0].Block)
	assert.Equal(t, byte('B'), entries[0].Data[0])
}

func TestGCHighUtilizationNotRetired(t *testing.T) {
	// Segment with 100% utilization (nothing shadowed) → never retired.
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
		makeWriteEntry(1, 1, 1, 'B'),
		makeWriteEntry(2, 1, 2, 'C'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.99})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 1)
	assert.Contains(t, filepath.Base(files[0]), "aaa")
}

func TestGCPreservesEntryData(t *testing.T) {
	// Verify that the data in retired+copied entries is byte-identical.
	dir := t.TempDir()

	writeData := make([]byte, testBlockSize)
	for i := range writeData {
		writeData[i] = byte(i % 251) // non-trivial pattern
	}
	crc := crc32.ChecksumIEEE(writeData)

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'X'), // will be shadowed
		{
			Op: "W", Sequence: 1, Block: 5, Length: uint32(len(writeData)),
			Checksum: crc, Data: writeData,
		},
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'B'), // shadows seg1 block 0
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.6})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 2)

	// Find the new segment.
	var newPath string
	for _, f := range files {
		if filepath.Base(f) != "disk.bbb.log" {
			newPath = f
		}
	}
	require.NotEmpty(t, newPath)

	entries := readAllEntries(t, newPath)
	require.Len(t, entries, 1)
	assert.Equal(t, uint64(5), entries[0].Block)
	assert.Equal(t, writeData, entries[0].Data)
	assert.True(t, entries[0].ValidateCRC())
}

func TestGCThreeSegmentsCascadingShadow(t *testing.T) {
	// Seg1: write block 0, write block 1
	// Seg2: write block 0 (shadows seg1 block 0)
	// Seg3: write block 0 (shadows seg2 block 0)
	// Seg1: 50% util (block 1 live). Seg2: 0% util. Seg3: 100%.
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
		makeWriteEntry(1, 1, 1, 'B'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'C'),
	})
	writeSegment(t, dir, "disk.ccc.log", testHeader("ccc"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'D'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.5})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	// Seg2 (0% util) retired, no live entries → no new segment for it.
	// Seg1 (50%) not retired (threshold 0.5, util == 0.5 not <).
	// Seg3 (100%) kept.
	require.Len(t, files, 2)

	names := make([]string, len(files))
	for i, f := range files {
		names[i] = filepath.Base(f)
	}
	assert.Contains(t, names, "disk.aaa.log")
	assert.Contains(t, names, "disk.ccc.log")
}

func TestGCEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.5})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no .log files")
}

// replayToFile runs runReplay programmatically, writing the replayed device
// image to outputPath from the log segments in logDir.
func replayToFile(t *testing.T, logDir, outputPath string) {
	t.Helper()
	err := runReplay(&replayArgs{LogDir: logDir, OutputPath: outputPath})
	require.NoError(t, err)
}

// filesEqual reports whether two files have identical contents.
func filesEqual(t *testing.T, pathA, pathB string) bool {
	t.Helper()
	dataA, err := os.ReadFile(pathA)
	require.NoError(t, err)
	dataB, err := os.ReadFile(pathB)
	require.NoError(t, err)
	return string(dataA) == string(dataB)
}

func TestGCReplayConsistencyPartialShadow(t *testing.T) {
	// This test demonstrates the ordering bug in GC.
	//
	// Segment A (TAI64N label from the past) has entries:
	//   entries 0-2: write blocks 10,11,12 — will be fully shadowed by B
	//   entry 3: writes blocks [0,1,2,3] with data 'A' — partially shadowed
	//
	// Segment B (TAI64N label slightly later) has entries:
	//   entry 0: writes blocks [0,1] with data 'B' — shadows A's blocks 0-1
	//   entry 1: writes blocks [10,11,12] — shadows A's entries 0-2
	//
	// Liveness analysis (newest-first):
	//   B entry 1 (blocks 10-12): live, adds 10-12 to covered set
	//   B entry 0 (blocks 0-1): live, adds 0-1 to covered set
	//   A entry 3 (blocks 0-3): blocks 0-1 covered, blocks 2-3 not → LIVE
	//   A entries 0-2 (blocks 10,11,12): all covered → DEAD
	//
	// A: liveWriteBytes = 16384 (entry 3), totalWriteBytes = 28672
	//    util = 57.1% → below 0.6 threshold → RETIRED
	//
	// GC copies A's live entry 3 (blocks 0-3, data 'A') into new segment N.
	// N gets a TAI64N label from NOW which sorts AFTER both A and B.
	//
	// Before GC replay order: A then B.
	//   block 0: A='A', B='B' → final 'B'
	//   block 1: A='A', B='B' → final 'B'
	//   block 2: A='A'        → final 'A'
	//   block 3: A='A'        → final 'A'
	//
	// After GC replay order: B then N (N sorts after B).
	//   block 0: B='B', N='A' → final 'A' (WRONG! should be 'B')
	//   block 1: B='B', N='A' → final 'A' (WRONG! should be 'B')
	//   block 2: N='A'        → final 'A'
	//   block 3: N='A'        → final 'A'
	dir := t.TempDir()

	// Use TAI64N-style labels so filenames sort chronologically,
	// and any new segment (with a current-time label) sorts after both.
	labelA := "40000000600000000000000a"
	labelB := "40000000600000000000000b"

	writeSegment(t, dir, "disk."+labelA+".log", testHeader(labelA), []*lbdlog.Entry{
		makeWriteEntry(10, 1, 0, 'D'), // block 10, will be shadowed by B
		makeWriteEntry(11, 1, 1, 'D'), // block 11, will be shadowed by B
		makeWriteEntry(12, 1, 2, 'D'), // block 12, will be shadowed by B
		makeWriteEntry(0, 4, 3, 'A'),  // blocks 0-3, partially shadowed
	})
	writeSegment(t, dir, "disk."+labelB+".log", testHeader(labelB), []*lbdlog.Entry{
		makeWriteEntry(0, 2, 0, 'B'),  // blocks 0-1
		makeWriteEntry(10, 3, 1, 'E'), // blocks 10-12
	})

	// Replay before GC.
	replayBefore := filepath.Join(t.TempDir(), "before.img")
	replayToFile(t, dir, replayBefore)

	// Run GC — A is at 57.1% util, below 0.6 threshold.
	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.6})
	require.NoError(t, err)

	// Replay after GC.
	replayAfter := filepath.Join(t.TempDir(), "after.img")
	replayToFile(t, dir, replayAfter)

	// The two replay outputs must be identical.
	assert.True(t, filesEqual(t, replayBefore, replayAfter),
		"replay before GC and after GC produced different device images")
}

func TestGCMixedWriteAndTrimLiveness(t *testing.T) {
	// Seg1: write block 0, write block 5
	// Seg2: trim block 0 (kills seg1's block 0 write), write block 10
	// Seg1 util: 50% (block 5 live, block 0 dead)
	// Seg2 util: 100% (trim has no write bytes, write block 10 is live)
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
		makeWriteEntry(5, 1, 1, 'B'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbdlog.Entry{
		makeTrimEntry(0, 1, 0),
		makeWriteEntry(10, 1, 1, 'C'),
	})

	// threshold 0.6 → seg1 (50%) retired
	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.6})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 2) // bbb + new segment with block 5

	var newPath string
	for _, f := range files {
		if filepath.Base(f) != "disk.bbb.log" {
			newPath = f
		}
	}
	require.NotEmpty(t, newPath)

	entries := readAllEntries(t, newPath)
	require.Len(t, entries, 1)
	assert.Equal(t, uint64(5), entries[0].Block)
	assert.Equal(t, byte('B'), entries[0].Data[0])
}

func TestGCExtentSplitting(t *testing.T) {
	// Segment A writes blocks [0..7] (8 blocks) with per-block fill.
	// Segment B shadows blocks [2..5] (4 blocks in the middle).
	// After GC, segment A should be retired and the new segment should
	// contain two split entries: blocks [0,2) and blocks [5,8), each
	// with correct data slices and CRCs.
	dir := t.TempDir()

	// Build an 8-block write where each block has a unique fill byte.
	dataA := make([]byte, 8*testBlockSize)
	for blk := 0; blk < 8; blk++ {
		fill := byte('a' + blk)
		for j := 0; j < testBlockSize; j++ {
			dataA[blk*testBlockSize+j] = fill
		}
	}

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		{
			Op: "W", Sequence: 0, Block: 0,
			Length:   uint32(len(dataA)),
			Checksum: crc32.ChecksumIEEE(dataA),
			Data:     dataA,
		},
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbdlog.Entry{
		makeWriteEntry(2, 4, 0, 'Z'), // shadows blocks 2-5
	})

	// Replay before GC.
	replayBefore := filepath.Join(t.TempDir(), "before.img")
	replayToFile(t, dir, replayBefore)

	// A: liveWriteBytes = 4*blockSize (blocks 0,1,6,7), totalWriteBytes = 8*blockSize
	// util = 50% → below 0.6 threshold → RETIRED
	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.6})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 2) // bbb + new segment

	var newPath string
	for _, f := range files {
		if filepath.Base(f) != "disk.bbb.log" {
			newPath = f
		}
	}
	require.NotEmpty(t, newPath, "expected new segment file")

	entries := readAllEntries(t, newPath)
	require.Len(t, entries, 2, "expected 2 split entries")

	// First split: blocks [0, 2)
	assert.Equal(t, uint64(0), entries[0].Block)
	assert.Equal(t, uint32(2*testBlockSize), entries[0].Length)
	assert.Equal(t, byte('a'), entries[0].Data[0])
	assert.Equal(t, byte('b'), entries[0].Data[testBlockSize])
	assert.True(t, entries[0].ValidateCRC())

	// Second split: blocks [6, 8)
	assert.Equal(t, uint64(6), entries[1].Block)
	assert.Equal(t, uint32(2*testBlockSize), entries[1].Length)
	assert.Equal(t, byte('g'), entries[1].Data[0])
	assert.Equal(t, byte('h'), entries[1].Data[testBlockSize])
	assert.True(t, entries[1].ValidateCRC())

	// Replay after GC must match.
	replayAfter := filepath.Join(t.TempDir(), "after.img")
	replayToFile(t, dir, replayAfter)

	assert.True(t, filesEqual(t, replayBefore, replayAfter),
		"replay before GC and after GC produced different device images")
}

func TestGCExtentSplittingTrim(t *testing.T) {
	// Verify extent splitting works for trim entries too.
	// Segment A trims blocks [0..4). Segment B writes block 2.
	// After GC, new segment should have two trim entries: [0,2) and [3,4).
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbdlog.Entry{
		makeTrimEntry(0, 4, 0),
		makeWriteEntry(10, 1, 1, 'X'), // keep something live to give write bytes
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbdlog.Entry{
		makeWriteEntry(2, 1, 0, 'B'), // shadows block 2 of the trim
		makeWriteEntry(10, 1, 1, 'Y'), // shadows block 10
	})

	// Replay before GC.
	replayBefore := filepath.Join(t.TempDir(), "before.img")
	replayToFile(t, dir, replayBefore)

	// A: liveWriteBytes = 0 (block 10 shadowed), totalWriteBytes = blockSize
	// util = 0% → below threshold → RETIRED
	err := runGC(&gcArgs{LogDir: dir, Threshold: 0.6})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 2) // bbb + new segment

	var newPath string
	for _, f := range files {
		if filepath.Base(f) != "disk.bbb.log" {
			newPath = f
		}
	}
	require.NotEmpty(t, newPath, "expected new segment file")

	entries := readAllEntries(t, newPath)
	require.Len(t, entries, 2, "expected 2 split trim entries")

	// First split trim: blocks [0, 2)
	assert.Equal(t, uint64(0), entries[0].Block)
	assert.Equal(t, uint32(2*testBlockSize), entries[0].Length)
	assert.True(t, entries[0].IsTrim())

	// Second split trim: blocks [3, 4)
	assert.Equal(t, uint64(3), entries[1].Block)
	assert.Equal(t, uint32(1*testBlockSize), entries[1].Length)
	assert.True(t, entries[1].IsTrim())

	// Replay after GC must match.
	replayAfter := filepath.Join(t.TempDir(), "after.img")
	replayToFile(t, dir, replayAfter)

	assert.True(t, filesEqual(t, replayBefore, replayAfter),
		"replay before GC and after GC produced different device images")
}
