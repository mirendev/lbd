package lbd

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQCow2CreateAndClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	assert.Equal(t, uint32(16), img.ClusterBits)
	assert.Equal(t, uint32(65536), img.ClusterSize)
	assert.Equal(t, uint64(1024*1024), img.VirtualSize)

	require.NoError(t, img.Close())

	// Verify file exists and is a valid qcow2
	img2, err := OpenQCow2ReadOnly(path)
	require.NoError(t, err)
	assert.Equal(t, uint64(1024*1024), img2.VirtualSize)
	assert.Equal(t, uint32(16), img2.ClusterBits)
	require.NoError(t, img2.Close())
}

func TestQCow2ReadZeros(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)
	defer img.Close()

	// Read from unallocated cluster should return zeros
	buf := make([]byte, 4096)
	n, err := img.ReadAt(buf, 0)
	require.NoError(t, err)
	assert.Equal(t, 4096, n)

	expected := make([]byte, 4096)
	assert.Equal(t, expected, buf)
}

func TestQCow2WriteReadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	// Write some data
	data := make([]byte, 4096)
	copy(data, []byte("Hello, qcow2-lz4! This is a test of the round-trip."))

	n, err := img.WriteAt(data, 0)
	require.NoError(t, err)
	assert.Equal(t, 4096, n)

	// Read it back
	readBuf := make([]byte, 4096)
	n, err = img.ReadAt(readBuf, 0)
	require.NoError(t, err)
	assert.Equal(t, 4096, n)
	assert.Equal(t, data, readBuf)

	// Close and reopen
	require.NoError(t, img.Close())

	img2, err := OpenQCow2ReadOnly(path)
	require.NoError(t, err)
	defer img2.Close()

	readBuf2 := make([]byte, 4096)
	n, err = img2.ReadAt(readBuf2, 0)
	require.NoError(t, err)
	assert.Equal(t, 4096, n)
	assert.Equal(t, data, readBuf2)
}

func TestQCow2WriteMultipleClusters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	// Write across multiple clusters
	data := make([]byte, 3*65536) // 3 clusters
	for i := range data {
		data[i] = byte(i % 251)
	}

	n, err := img.WriteAt(data, 0)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)

	// Read it back
	readBuf := make([]byte, len(data))
	n, err = img.ReadAt(readBuf, 0)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, readBuf)

	require.NoError(t, img.Close())
}

func TestQCow2WriteAtOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	// Write at non-zero offset within a cluster
	data := []byte("test data at offset")
	padded := make([]byte, len(data))
	copy(padded, data)

	n, err := img.WriteAt(padded, 8192)
	require.NoError(t, err)
	assert.Equal(t, len(padded), n)

	// Read it back
	readBuf := make([]byte, len(padded))
	n, err = img.ReadAt(readBuf, 8192)
	require.NoError(t, err)
	assert.Equal(t, padded, readBuf)

	// Verify zeros before the write
	zeros := make([]byte, 8192)
	readZeros := make([]byte, 8192)
	n, err = img.ReadAt(readZeros, 0)
	require.NoError(t, err)
	assert.Equal(t, zeros, readZeros)

	require.NoError(t, img.Close())
}

func TestQCow2Trim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	// Write data
	data := make([]byte, 65536)
	for i := range data {
		data[i] = 0xFF
	}
	_, err = img.WriteAt(data, 0)
	require.NoError(t, err)

	// Trim the full cluster
	err = img.Trim(0, 65536)
	require.NoError(t, err)

	// Read back should be zeros
	readBuf := make([]byte, 65536)
	_, err = img.ReadAt(readBuf, 0)
	require.NoError(t, err)
	assert.Equal(t, make([]byte, 65536), readBuf)

	require.NoError(t, img.Close())
}

func TestQCow2PartialTrim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	// Write data
	data := make([]byte, 65536)
	for i := range data {
		data[i] = byte(i % 256)
	}
	_, err = img.WriteAt(data, 0)
	require.NoError(t, err)

	// Trim only the first 4096 bytes
	err = img.Trim(0, 4096)
	require.NoError(t, err)

	// First 4096 should be zeros
	readBuf := make([]byte, 65536)
	_, err = img.ReadAt(readBuf, 0)
	require.NoError(t, err)

	assert.Equal(t, make([]byte, 4096), readBuf[:4096])
	// Rest should be unchanged
	assert.Equal(t, data[4096:], readBuf[4096:])

	require.NoError(t, img.Close())
}

func TestQCow2RandomDataRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	// Write random data (won't compress well)
	data := make([]byte, 65536)
	_, err = rand.Read(data)
	require.NoError(t, err)

	_, err = img.WriteAt(data, 0)
	require.NoError(t, err)

	// Close and reopen to verify persistence
	require.NoError(t, img.Close())

	img2, err := OpenQCow2ReadOnly(path)
	require.NoError(t, err)

	readBuf := make([]byte, 65536)
	_, err = img2.ReadAt(readBuf, 0)
	require.NoError(t, err)
	assert.Equal(t, data, readBuf)

	require.NoError(t, img2.Close())
}

func TestQCow2CrossClusterWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	// Write across a cluster boundary
	data := make([]byte, 8192)
	for i := range data {
		data[i] = byte(i % 253)
	}

	offset := int64(65536 - 4096) // starts 4096 before cluster boundary
	_, err = img.WriteAt(data, offset)
	require.NoError(t, err)

	readBuf := make([]byte, 8192)
	_, err = img.ReadAt(readBuf, offset)
	require.NoError(t, err)
	assert.Equal(t, data, readBuf)

	require.NoError(t, img.Close())
}

func TestQCow2ExtractToFlat(t *testing.T) {
	qcow2Path := filepath.Join(t.TempDir(), "test.qcow2")
	flatPath := filepath.Join(t.TempDir(), "test.flat")

	// Create qcow2 with some data
	img, err := CreateQCow2(qcow2Path, 256*1024, 16) // 256K = 4 clusters
	require.NoError(t, err)

	data1 := make([]byte, 4096)
	copy(data1, []byte("cluster 0 data"))
	_, err = img.WriteAt(data1, 0)
	require.NoError(t, err)

	data2 := make([]byte, 4096)
	copy(data2, []byte("cluster 2 data"))
	_, err = img.WriteAt(data2, 2*65536)
	require.NoError(t, err)

	require.NoError(t, img.Close())

	// Reopen and extract
	img2, err := OpenQCow2ReadOnly(qcow2Path)
	require.NoError(t, err)

	outFile, err := os.Create(flatPath)
	require.NoError(t, err)

	err = outFile.Truncate(int64(img2.VirtualSize))
	require.NoError(t, err)

	err = img2.ExtractTo(outFile, int64(img2.VirtualSize))
	require.NoError(t, err)
	outFile.Close()
	img2.Close()

	// Verify flat file contents
	flatData, err := os.ReadFile(flatPath)
	require.NoError(t, err)
	assert.Equal(t, 256*1024, len(flatData))

	// First 4096 should match data1
	assert.True(t, bytes.HasPrefix(flatData, data1))

	// Offset 2*65536 should match data2
	assert.Equal(t, data2, flatData[2*65536:2*65536+4096])

	// Everything else should be zeros
	assert.Equal(t, make([]byte, 65536-4096), flatData[4096:65536])
}

func TestQCow2OverwriteFitsInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	// Write a cluster with compressible data
	data := bytes.Repeat([]byte("AAAA"), 65536/4)
	_, err = img.WriteAt(data, 0)
	require.NoError(t, err)

	allocAfterFirst := img.AllocOffset

	// Overwrite with same-size compressible data (should fit in-place)
	data2 := bytes.Repeat([]byte("BBBB"), 65536/4)
	_, err = img.WriteAt(data2, 0)
	require.NoError(t, err)

	// AllocOffset should NOT grow — data was written in-place
	assert.Equal(t, allocAfterFirst, img.AllocOffset,
		"alloc_offset should not grow for in-place rewrite")
	assert.Equal(t, uint64(0), img.FreeListHead,
		"free list should be empty for in-place rewrite")

	// Read it back to verify correctness
	readBuf := make([]byte, 65536)
	_, err = img.ReadAt(readBuf, 0)
	require.NoError(t, err)
	assert.Equal(t, data2, readBuf)

	require.NoError(t, img.Close())
}

func TestQCow2OverwriteLargerGoesToFreeList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	// Write a highly compressible cluster (will be small on disk)
	data := bytes.Repeat([]byte{0xAA}, 65536)
	_, err = img.WriteAt(data, 0)
	require.NoError(t, err)

	// Now write random (incompressible) data — won't fit in old allocation
	randData := make([]byte, 65536)
	_, err = rand.Read(randData)
	require.NoError(t, err)
	_, err = img.WriteAt(randData, 0)
	require.NoError(t, err)

	// Free list should now have the old allocation
	assert.NotEqual(t, uint64(0), img.FreeListHead,
		"free list should contain old allocation")

	// Read it back to verify correctness
	readBuf := make([]byte, 65536)
	_, err = img.ReadAt(readBuf, 0)
	require.NoError(t, err)
	assert.Equal(t, randData, readBuf)

	require.NoError(t, img.Close())
}

func TestQCow2FreeListReuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	// Write random data to cluster 0 (uncompressible, takes cluster_size on disk)
	randData := make([]byte, 65536)
	_, err = rand.Read(randData)
	require.NoError(t, err)
	_, err = img.WriteAt(randData, 0)
	require.NoError(t, err)

	// Trim cluster 0 — old cluster_size allocation goes to free list
	err = img.Trim(0, 65536)
	require.NoError(t, err)

	assert.NotEqual(t, uint64(0), img.FreeListHead,
		"trim should create free list entry")

	allocBeforeReuse := img.AllocOffset

	// Write another uncompressible cluster to cluster 1 — should reuse free list entry
	randData2 := make([]byte, 65536)
	_, err = rand.Read(randData2)
	require.NoError(t, err)
	_, err = img.WriteAt(randData2, 65536) // cluster 1
	require.NoError(t, err)

	// AllocOffset should NOT have grown because we reused the free space
	assert.Equal(t, allocBeforeReuse, img.AllocOffset,
		"free list entry should have been reused, alloc_offset unchanged")

	// Read cluster 1 back to verify
	readBuf := make([]byte, 65536)
	_, err = img.ReadAt(readBuf, 65536)
	require.NoError(t, err)
	assert.Equal(t, randData2, readBuf)

	// Read cluster 0 back — should be zeros (trimmed)
	_, err = img.ReadAt(readBuf, 0)
	require.NoError(t, err)
	assert.Equal(t, make([]byte, 65536), readBuf)

	require.NoError(t, img.Close())
}

func TestQCow2FreeListPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	// Write then overwrite to create a free list entry
	data := bytes.Repeat([]byte{0xAA}, 65536)
	_, err = img.WriteAt(data, 0)
	require.NoError(t, err)

	randData := make([]byte, 65536)
	_, err = rand.Read(randData)
	require.NoError(t, err)
	_, err = img.WriteAt(randData, 0)
	require.NoError(t, err)

	freeHead := img.FreeListHead
	assert.NotEqual(t, uint64(0), freeHead)

	require.NoError(t, img.Close())

	// Reopen and verify free list head persisted
	img2, err := OpenQCow2(path)
	require.NoError(t, err)

	assert.Equal(t, freeHead, img2.FreeListHead,
		"free_list_head should persist across close/reopen")

	// Read the data to verify integrity
	readBuf := make([]byte, 65536)
	_, err = img2.ReadAt(readBuf, 0)
	require.NoError(t, err)
	assert.Equal(t, randData, readBuf)

	require.NoError(t, img2.Close())
}

func TestQCow2TrimFreesExtent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	// Write data
	data := bytes.Repeat([]byte{0xFF}, 65536)
	_, err = img.WriteAt(data, 0)
	require.NoError(t, err)

	assert.Equal(t, uint64(0), img.FreeListHead)

	// Full-cluster trim should free the extent
	err = img.Trim(0, 65536)
	require.NoError(t, err)

	assert.NotEqual(t, uint64(0), img.FreeListHead,
		"trim should add old extent to free list")

	// Read back should be zeros
	readBuf := make([]byte, 65536)
	_, err = img.ReadAt(readBuf, 0)
	require.NoError(t, err)
	assert.Equal(t, make([]byte, 65536), readBuf)

	require.NoError(t, img.Close())
}

func TestQCow2L2CRC32CCorruptionDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.qcow2")

	// Create image and write some data to force L2 table allocation
	img, err := CreateQCow2(path, 1024*1024, 16)
	require.NoError(t, err)

	data := bytes.Repeat([]byte("X"), 4096)
	_, err = img.WriteAt(data, 0)
	require.NoError(t, err)

	require.NoError(t, img.Close())

	// Verify we can read it back cleanly first
	img2, err := OpenQCow2ReadOnly(path)
	require.NoError(t, err)
	readBuf := make([]byte, 4096)
	_, err = img2.ReadAt(readBuf, 0)
	require.NoError(t, err)
	assert.Equal(t, data, readBuf)
	require.NoError(t, img2.Close())

	// Now corrupt a byte in the L2 table on disk.
	// The L2 table is at the offset stored in L1[0].
	img3, err := OpenQCow2(path)
	require.NoError(t, err)
	l2Offset := img3.L1Table[0]
	require.NotEqual(t, uint64(0), l2Offset, "L2 table should be allocated")
	img3.Close()

	// Corrupt a byte in the L2 table entries area (not the CRC itself)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	var corruptBuf [1]byte
	_, err = f.ReadAt(corruptBuf[:], int64(l2Offset)+4)
	require.NoError(t, err)
	corruptBuf[0] ^= 0xFF // flip all bits
	_, err = f.WriteAt(corruptBuf[:], int64(l2Offset)+4)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Reopen and try to read — should get CRC error
	img4, err := OpenQCow2ReadOnly(path)
	require.NoError(t, err)
	defer img4.Close()

	_, err = img4.ReadAt(readBuf, 0)
	require.Error(t, err, "expected CRC32C mismatch error after corruption")
	assert.Contains(t, err.Error(), "CRC32C mismatch")
}

func TestQCow2CompatibleWithLbdctl(t *testing.T) {
	// Create a flat file, use the Go qcow2 writer to create an image,
	// then verify the Go reader can read it back correctly.
	dir := t.TempDir()
	qcow2Path := filepath.Join(dir, "test.qcow2")

	// Create an image and write various patterns
	img, err := CreateQCow2(qcow2Path, 1024*1024, 16)
	require.NoError(t, err)

	// Write to multiple offsets
	patterns := []struct {
		offset int64
		data   []byte
	}{
		{0, bytes.Repeat([]byte("A"), 4096)},
		{65536, bytes.Repeat([]byte("B"), 4096)},
		{65536 + 4096, bytes.Repeat([]byte("C"), 4096)},
	}

	for _, p := range patterns {
		_, err := img.WriteAt(p.data, p.offset)
		require.NoError(t, err)
	}

	require.NoError(t, img.Close())

	// Reopen and verify all patterns
	img2, err := OpenQCow2ReadOnly(qcow2Path)
	require.NoError(t, err)
	defer img2.Close()

	for _, p := range patterns {
		buf := make([]byte, len(p.data))
		_, err := img2.ReadAt(buf, p.offset)
		require.NoError(t, err)
		assert.Equal(t, p.data, buf, "mismatch at offset %d", p.offset)
	}
}
