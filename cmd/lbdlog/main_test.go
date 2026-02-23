package main

import (
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"miren.dev/lbd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Helpers for GC integration tests ---

const testBlockSize = 4096

func testHeader(label string) lbd.Header {
	return lbd.Header{
		Version:      2,
		BlockSize:    testBlockSize,
		SegmentLabel: label,
		DeviceSize:   1024 * 1024,
		BackingPath:  "/tmp/test.img",
	}
}

func writeSegment(t *testing.T, dir, name string, hdr lbd.Header, entries []*lbd.Entry) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	wr, err := lbd.NewWriter(f, hdr)
	require.NoError(t, err)

	for _, e := range entries {
		require.NoError(t, wr.WriteEntry(e))
	}
	return path
}

func makeWriteEntry(block uint64, numBlocks int, seq uint64, fill byte) *lbd.Entry {
	data := make([]byte, numBlocks*testBlockSize)
	for i := range data {
		data[i] = fill
	}
	return &lbd.Entry{
		Op:       "W",
		Sequence: seq,
		Block:    block,
		Length:   uint32(len(data)),
		Checksum: crc32.ChecksumIEEE(data),
		Data:     data,
	}
}

func makeTrimEntry(block uint64, numBlocks int, seq uint64) *lbd.Entry {
	return &lbd.Entry{
		Op:       "T",
		Sequence: seq,
		Block:    block,
		Length:   uint32(numBlocks * testBlockSize),
	}
}

func readAllEntries(t *testing.T, path string) []*lbd.Entry {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	rd, err := lbd.NewReader(f)
	require.NoError(t, err)

	var entries []*lbd.Entry
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
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbd.Entry{
		makeWriteEntry(10, 1, 0, 'B'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 50})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	assert.Len(t, files, 2)
}

func TestGCFullShadow(t *testing.T) {
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'B'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 50})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 1)
	assert.Contains(t, filepath.Base(files[0]), "bbb")

	entries := readAllEntries(t, files[0])
	require.Len(t, entries, 1)
	assert.Equal(t, byte('B'), entries[0].Data[0])
}

func TestGCPartialShadow(t *testing.T) {
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
		makeWriteEntry(5, 1, 1, 'C'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'B'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 60})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 2)

	var newSegPath string
	for _, f := range files {
		if filepath.Base(f) != "disk.bbb.log" {
			newSegPath = f
		}
	}
	require.NotEmpty(t, newSegPath, "expected new segment file")

	assert.NotContains(t, filepath.Base(newSegPath), "aaa",
		"new segment should have a fresh label")

	entries := readAllEntries(t, newSegPath)
	require.Len(t, entries, 1)
	assert.Equal(t, uint64(5), entries[0].Block)
	assert.Equal(t, uint32(testBlockSize), entries[0].Length)
	assert.Equal(t, byte('C'), entries[0].Data[0])
	assert.True(t, entries[0].ValidateCRC())
}

func TestGCDryRunDoesNotModify(t *testing.T) {
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'B'),
	})

	filesBefore := logFilesInDir(t, dir)

	err := runGC(&gcArgs{LogDir: dir, Threshold: 50, DryRun: true})
	require.NoError(t, err)

	filesAfter := logFilesInDir(t, dir)
	assert.Equal(t, filesBefore, filesAfter, "dry-run should not change files")
}

func TestGCTrimShadowsWrite(t *testing.T) {
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbd.Entry{
		makeTrimEntry(0, 1, 0),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 50})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 1)
	assert.Contains(t, filepath.Base(files[0]), "bbb")
}

func TestGCTrimOnlySegmentKept(t *testing.T) {
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeTrimEntry(0, 10, 0),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 50})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 1)
	assert.Contains(t, filepath.Base(files[0]), "aaa")
}

func TestGCMultiBlockShadowing(t *testing.T) {
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeWriteEntry(0, 4, 0, 'A'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbd.Entry{
		makeWriteEntry(0, 2, 0, 'B'),
		makeWriteEntry(2, 2, 1, 'C'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 50})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 1)
	assert.Contains(t, filepath.Base(files[0]), "bbb")
}

func TestGCWithinSegmentShadowing(t *testing.T) {
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
		makeWriteEntry(0, 1, 1, 'B'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 50})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 1)
	assert.Contains(t, filepath.Base(files[0]), "aaa")
}

func TestGCWithinSegmentShadowingRetired(t *testing.T) {
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
		makeWriteEntry(0, 1, 1, 'B'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 60})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 1)
	assert.NotContains(t, filepath.Base(files[0]), "aaa",
		"new segment should have a fresh label, not reuse the retired label")

	entries := readAllEntries(t, files[0])
	require.Len(t, entries, 1)
	assert.Equal(t, uint64(0), entries[0].Block)
	assert.Equal(t, byte('B'), entries[0].Data[0])
}

func TestGCHighUtilizationNotRetired(t *testing.T) {
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
		makeWriteEntry(1, 1, 1, 'B'),
		makeWriteEntry(2, 1, 2, 'C'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 99})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 1)
	assert.Contains(t, filepath.Base(files[0]), "aaa")
}

func TestGCPreservesEntryData(t *testing.T) {
	dir := t.TempDir()

	writeData := make([]byte, testBlockSize)
	for i := range writeData {
		writeData[i] = byte(i % 251)
	}
	crc := crc32.ChecksumIEEE(writeData)

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'X'),
		{
			Op: "W", Sequence: 1, Block: 5, Length: uint32(len(writeData)),
			Checksum: crc, Data: writeData,
		},
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'B'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 60})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 2)

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
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
		makeWriteEntry(1, 1, 1, 'B'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'C'),
	})
	writeSegment(t, dir, "disk.ccc.log", testHeader("ccc"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'D'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 50})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
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
	err := runGC(&gcArgs{LogDir: dir, Threshold: 50})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no .log files")
}

// replayToFile runs runReplay programmatically.
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
	dir := t.TempDir()

	labelA := "40000000600000000000000a"
	labelB := "40000000600000000000000b"

	writeSegment(t, dir, "disk."+labelA+".log", testHeader(labelA), []*lbd.Entry{
		makeWriteEntry(10, 1, 0, 'D'),
		makeWriteEntry(11, 1, 1, 'D'),
		makeWriteEntry(12, 1, 2, 'D'),
		makeWriteEntry(0, 4, 3, 'A'),
	})
	writeSegment(t, dir, "disk."+labelB+".log", testHeader(labelB), []*lbd.Entry{
		makeWriteEntry(0, 2, 0, 'B'),
		makeWriteEntry(10, 3, 1, 'E'),
	})

	replayBefore := filepath.Join(t.TempDir(), "before.img")
	replayToFile(t, dir, replayBefore)

	err := runGC(&gcArgs{LogDir: dir, Threshold: 60})
	require.NoError(t, err)

	replayAfter := filepath.Join(t.TempDir(), "after.img")
	replayToFile(t, dir, replayAfter)

	assert.True(t, filesEqual(t, replayBefore, replayAfter),
		"replay before GC and after GC produced different device images")
}

func TestGCMixedWriteAndTrimLiveness(t *testing.T) {
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeWriteEntry(0, 1, 0, 'A'),
		makeWriteEntry(5, 1, 1, 'B'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbd.Entry{
		makeTrimEntry(0, 1, 0),
		makeWriteEntry(10, 1, 1, 'C'),
	})

	err := runGC(&gcArgs{LogDir: dir, Threshold: 60})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 2)

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
	dir := t.TempDir()

	dataA := make([]byte, 8*testBlockSize)
	for blk := 0; blk < 8; blk++ {
		fill := byte('a' + blk)
		for j := 0; j < testBlockSize; j++ {
			dataA[blk*testBlockSize+j] = fill
		}
	}

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		{
			Op: "W", Sequence: 0, Block: 0,
			Length:   uint32(len(dataA)),
			Checksum: crc32.ChecksumIEEE(dataA),
			Data:     dataA,
		},
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbd.Entry{
		makeWriteEntry(2, 4, 0, 'Z'),
	})

	replayBefore := filepath.Join(t.TempDir(), "before.img")
	replayToFile(t, dir, replayBefore)

	err := runGC(&gcArgs{LogDir: dir, Threshold: 60})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 2)

	var newPath string
	for _, f := range files {
		if filepath.Base(f) != "disk.bbb.log" {
			newPath = f
		}
	}
	require.NotEmpty(t, newPath, "expected new segment file")

	entries := readAllEntries(t, newPath)
	require.Len(t, entries, 2, "expected 2 split entries")

	assert.Equal(t, uint64(0), entries[0].Block)
	assert.Equal(t, uint32(2*testBlockSize), entries[0].Length)
	assert.Equal(t, byte('a'), entries[0].Data[0])
	assert.Equal(t, byte('b'), entries[0].Data[testBlockSize])
	assert.True(t, entries[0].ValidateCRC())

	assert.Equal(t, uint64(6), entries[1].Block)
	assert.Equal(t, uint32(2*testBlockSize), entries[1].Length)
	assert.Equal(t, byte('g'), entries[1].Data[0])
	assert.Equal(t, byte('h'), entries[1].Data[testBlockSize])
	assert.True(t, entries[1].ValidateCRC())

	replayAfter := filepath.Join(t.TempDir(), "after.img")
	replayToFile(t, dir, replayAfter)

	assert.True(t, filesEqual(t, replayBefore, replayAfter),
		"replay before GC and after GC produced different device images")
}

func TestGCExtentSplittingTrim(t *testing.T) {
	dir := t.TempDir()

	writeSegment(t, dir, "disk.aaa.log", testHeader("aaa"), []*lbd.Entry{
		makeTrimEntry(0, 4, 0),
		makeWriteEntry(10, 1, 1, 'X'),
	})
	writeSegment(t, dir, "disk.bbb.log", testHeader("bbb"), []*lbd.Entry{
		makeWriteEntry(2, 1, 0, 'B'),
		makeWriteEntry(10, 1, 1, 'Y'),
	})

	replayBefore := filepath.Join(t.TempDir(), "before.img")
	replayToFile(t, dir, replayBefore)

	err := runGC(&gcArgs{LogDir: dir, Threshold: 60})
	require.NoError(t, err)

	files := logFilesInDir(t, dir)
	require.Len(t, files, 2)

	var newPath string
	for _, f := range files {
		if filepath.Base(f) != "disk.bbb.log" {
			newPath = f
		}
	}
	require.NotEmpty(t, newPath, "expected new segment file")

	entries := readAllEntries(t, newPath)
	require.Len(t, entries, 2, "expected 2 split trim entries")

	assert.Equal(t, uint64(0), entries[0].Block)
	assert.Equal(t, uint32(2*testBlockSize), entries[0].Length)
	assert.True(t, entries[0].IsTrim())

	assert.Equal(t, uint64(3), entries[1].Block)
	assert.Equal(t, uint32(1*testBlockSize), entries[1].Length)
	assert.True(t, entries[1].IsTrim())

	replayAfter := filepath.Join(t.TempDir(), "after.img")
	replayToFile(t, dir, replayAfter)

	assert.True(t, filesEqual(t, replayBefore, replayAfter),
		"replay before GC and after GC produced different device images")
}
