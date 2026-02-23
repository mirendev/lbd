package lbd

import (
	"bytes"
	"hash/crc32"
	"io"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/pierrec/lz4/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encodeCBOR encodes v as CBOR and appends to buf.
func encodeCBOR(t *testing.T, buf *bytes.Buffer, v interface{}) {
	t.Helper()
	b, err := cbor.Marshal(v)
	require.NoError(t, err)
	buf.Write(b)
}

// compressLZ4 compresses data using LZ4 block compression.
func compressLZ4(t *testing.T, data []byte) []byte {
	t.Helper()
	dst := make([]byte, lz4.CompressBlockBound(len(data)))
	n, err := lz4.CompressBlock(data, dst, nil)
	require.NoError(t, err)
	require.Greater(t, n, 0, "LZ4 compression produced no output")
	return dst[:n]
}

func buildLogFile(t *testing.T, hdr Header, entries []Entry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	encodeCBOR(t, &buf, hdr)
	for _, e := range entries {
		// LZ4-compress write entry data before encoding
		if e.IsWrite() && len(e.Data) > 0 {
			e.Data = compressLZ4(t, e.Data)
		}
		encodeCBOR(t, &buf, e)
	}
	return &buf
}

func TestReadHeader(t *testing.T) {
	hdr := Header{
		Version:     2,
		BlockSize:   4096,
		SegmentLabel: "0000000000000000",
		DeviceSize:  10 * 1024 * 1024,
		BackingPath: "/tmp/test.img",
	}

	buf := buildLogFile(t, hdr, nil)
	rd, err := NewReader(buf)
	require.NoError(t, err)

	assert.Equal(t, uint32(2), rd.Header.Version)
	assert.Equal(t, uint32(4096), rd.Header.BlockSize)
	assert.Equal(t, "0000000000000000", rd.Header.SegmentLabel)
	assert.Equal(t, uint64(10*1024*1024), rd.Header.DeviceSize)
	assert.Equal(t, "/tmp/test.img", rd.Header.BackingPath)

	// No entries
	_, err = rd.Next()
	assert.ErrorIs(t, err, io.EOF)
}

func TestReadWriteEntry(t *testing.T) {
	data := []byte("HELLO_LBD_TEST_DATA_1234567890")
	// Pad to 4096 bytes
	padded := make([]byte, 4096)
	copy(padded, data)

	crc := crc32.ChecksumIEEE(padded)

	hdr := Header{
		Version:     2,
		BlockSize:   4096,
		SegmentLabel: "0000000000000000",
		DeviceSize:  10 * 1024 * 1024,
		BackingPath: "/tmp/test.img",
	}

	entries := []Entry{
		{
			Op:          "W",
			TimestampNS: 1700000000000000000,
			Sequence:    0,
			Block:       0,
			Length:      4096,
			Checksum:    crc,
			Data:        padded,
		},
	}

	buf := buildLogFile(t, hdr, entries)
	rd, err := NewReader(buf)
	require.NoError(t, err)

	e, err := rd.Next()
	require.NoError(t, err)

	assert.True(t, e.IsWrite())
	assert.False(t, e.IsTrim())
	assert.Equal(t, uint64(0), e.Sequence)
	assert.Equal(t, uint64(0), e.Block)
	assert.Equal(t, uint32(4096), e.Length)
	assert.Equal(t, crc, e.Checksum)
	assert.Equal(t, padded, e.Data)
	assert.True(t, e.ValidateCRC())

	_, err = rd.Next()
	assert.ErrorIs(t, err, io.EOF)
}

func TestReadTrimEntry(t *testing.T) {
	hdr := Header{
		Version:     2,
		BlockSize:   4096,
		SegmentLabel: "0000000000000001",
		DeviceSize:  100 * 1024 * 1024,
		BackingPath: "/tmp/big.img",
	}

	entries := []Entry{
		{
			Op:          "T",
			TimestampNS: 1700000001000000000,
			Sequence:    5,
			Block:       10,
			Length:      8192,
		},
	}

	buf := buildLogFile(t, hdr, entries)
	rd, err := NewReader(buf)
	require.NoError(t, err)

	e, err := rd.Next()
	require.NoError(t, err)

	assert.True(t, e.IsTrim())
	assert.False(t, e.IsWrite())
	assert.Equal(t, uint64(5), e.Sequence)
	assert.Equal(t, uint64(10), e.Block)
	assert.Equal(t, uint32(8192), e.Length)
	assert.Equal(t, uint32(0), e.Checksum)
	assert.Nil(t, e.Data)
	assert.True(t, e.ValidateCRC())
}

func TestReadMultipleEntries(t *testing.T) {
	data1 := make([]byte, 4096)
	copy(data1, []byte("BLOCK_ZERO"))
	crc1 := crc32.ChecksumIEEE(data1)

	data2 := make([]byte, 4096)
	copy(data2, []byte("BLOCK_TWO"))
	crc2 := crc32.ChecksumIEEE(data2)

	hdr := Header{
		Version:     2,
		BlockSize:   4096,
		SegmentLabel: "0000000000000000",
		DeviceSize:  10 * 1024 * 1024,
		BackingPath: "/tmp/test.img",
	}

	entries := []Entry{
		{Op: "W", TimestampNS: 100, Sequence: 0, Block: 0, Length: 4096, Checksum: crc1, Data: data1},
		{Op: "W", TimestampNS: 200, Sequence: 1, Block: 2, Length: 4096, Checksum: crc2, Data: data2},
		{Op: "T", TimestampNS: 300, Sequence: 2, Block: 5, Length: 8192},
	}

	buf := buildLogFile(t, hdr, entries)
	rd, err := NewReader(buf)
	require.NoError(t, err)

	all, err := rd.ReadAll()
	require.NoError(t, err)
	require.Len(t, all, 3)

	assert.True(t, all[0].IsWrite())
	assert.Equal(t, uint64(0), all[0].Sequence)
	assert.True(t, all[0].ValidateCRC())

	assert.True(t, all[1].IsWrite())
	assert.Equal(t, uint64(1), all[1].Sequence)
	assert.Equal(t, uint64(2), all[1].Block)
	assert.True(t, all[1].ValidateCRC())

	assert.True(t, all[2].IsTrim())
	assert.Equal(t, uint64(2), all[2].Sequence)
	assert.Equal(t, uint64(5), all[2].Block)
	assert.Equal(t, uint32(8192), all[2].Length)
}

func TestBadCRC(t *testing.T) {
	data := make([]byte, 4096)
	copy(data, []byte("SOME DATA"))
	badCRC := uint32(0xDEADBEEF)

	hdr := Header{
		Version:     2,
		BlockSize:   4096,
		SegmentLabel: "0000000000000000",
		DeviceSize:  10 * 1024 * 1024,
		BackingPath: "/tmp/test.img",
	}

	entries := []Entry{
		{Op: "W", TimestampNS: 100, Sequence: 0, Block: 0, Length: 4096, Checksum: badCRC, Data: data},
	}

	buf := buildLogFile(t, hdr, entries)
	rd, err := NewReader(buf)
	require.NoError(t, err)

	e, err := rd.Next()
	require.NoError(t, err)
	assert.False(t, e.ValidateCRC(), "CRC should not validate with wrong checksum")
}

func TestEmptyReader(t *testing.T) {
	_, err := NewReader(bytes.NewReader(nil))
	assert.Error(t, err, "should fail on empty input")
}

func TestUnknownKeysIgnored(t *testing.T) {
	// Build a header with an extra key (99) that the Go struct doesn't know about.
	// The CBOR library should ignore unknown keys by default.
	raw := map[int]interface{}{
		1:  uint64(2),
		2:  uint64(4096),
		3:  "0000000000000000",
		4:  uint64(10485760),
		5:  "/tmp/test.img",
		99: "future_field",
	}

	var buf bytes.Buffer
	b, err := cbor.Marshal(raw)
	require.NoError(t, err)
	buf.Write(b)

	rd, err := NewReader(&buf)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), rd.Header.Version)
	assert.Equal(t, "/tmp/test.img", rd.Header.BackingPath)
}

func TestLargeData(t *testing.T) {
	// 128K write (32 blocks)
	data := make([]byte, 128*1024)
	for i := range data {
		data[i] = byte(i % 251) // deterministic pattern
	}
	crc := crc32.ChecksumIEEE(data)

	hdr := Header{
		Version:     2,
		BlockSize:   4096,
		SegmentLabel: "0000000000000000",
		DeviceSize:  1 * 1024 * 1024 * 1024,
		BackingPath: "/tmp/large.img",
	}

	entries := []Entry{
		{Op: "W", TimestampNS: 500, Sequence: 0, Block: 0, Length: 128 * 1024, Checksum: crc, Data: data},
	}

	buf := buildLogFile(t, hdr, entries)
	rd, err := NewReader(buf)
	require.NoError(t, err)

	e, err := rd.Next()
	require.NoError(t, err)
	assert.Equal(t, uint32(128*1024), e.Length)
	assert.Equal(t, data, e.Data)
	assert.True(t, e.ValidateCRC())
}

func TestWriterRoundTrip(t *testing.T) {
	data1 := make([]byte, 4096)
	copy(data1, []byte("WRITER_TEST_BLOCK_0"))
	crc1 := crc32.ChecksumIEEE(data1)

	data2 := make([]byte, 4096)
	copy(data2, []byte("WRITER_TEST_BLOCK_1"))
	crc2 := crc32.ChecksumIEEE(data2)

	hdr := Header{
		Version:      2,
		BlockSize:    4096,
		SegmentLabel: "4000000065b0a23c0bebc200",
		DeviceSize:   10 * 1024 * 1024,
		BackingPath:  "/tmp/writer-test.img",
	}

	entries := []*Entry{
		{Op: "W", TimestampNS: 100, Sequence: 0, Block: 0, Length: 4096, Checksum: crc1, Data: data1},
		{Op: "T", TimestampNS: 200, Sequence: 1, Block: 5, Length: 8192},
		{Op: "W", TimestampNS: 300, Sequence: 2, Block: 2, Length: 4096, Checksum: crc2, Data: data2},
	}

	// Write
	var buf bytes.Buffer
	wr, err := NewWriter(&buf, hdr)
	require.NoError(t, err)

	for _, e := range entries {
		require.NoError(t, wr.WriteEntry(e))
	}

	// Verify original data was not mutated by compression
	assert.Equal(t, data1, entries[0].Data)
	assert.Equal(t, data2, entries[2].Data)

	// Read back
	rd, err := NewReader(&buf)
	require.NoError(t, err)

	assert.Equal(t, hdr.Version, rd.Header.Version)
	assert.Equal(t, hdr.BlockSize, rd.Header.BlockSize)
	assert.Equal(t, hdr.SegmentLabel, rd.Header.SegmentLabel)
	assert.Equal(t, hdr.DeviceSize, rd.Header.DeviceSize)
	assert.Equal(t, hdr.BackingPath, rd.Header.BackingPath)

	all, err := rd.ReadAll()
	require.NoError(t, err)
	require.Len(t, all, 3)

	// First write
	assert.True(t, all[0].IsWrite())
	assert.Equal(t, data1, all[0].Data)
	assert.True(t, all[0].ValidateCRC())

	// Trim
	assert.True(t, all[1].IsTrim())
	assert.Equal(t, uint64(5), all[1].Block)
	assert.Equal(t, uint32(8192), all[1].Length)

	// Second write
	assert.True(t, all[2].IsWrite())
	assert.Equal(t, data2, all[2].Data)
	assert.True(t, all[2].ValidateCRC())
}
