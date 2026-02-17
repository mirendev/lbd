// Package lbd reads LBD CBOR log files (format version 2).
//
// Log files are CBOR sequences (RFC 8742): a header map followed by
// zero or more entry maps concatenated without framing.
package lbd

import (
	"fmt"
	"hash/crc32"
	"io"

	"github.com/fxamacker/cbor/v2"
	"github.com/pierrec/lz4/v4"
)

// Header is the first CBOR item in a log file.
type Header struct {
	Version     uint32 `cbor:"1,keyasint"`
	BlockSize   uint32 `cbor:"2,keyasint"`
	SegmentLabel string `cbor:"3,keyasint"`
	DeviceSize  uint64 `cbor:"4,keyasint"`
	BackingPath string `cbor:"5,keyasint"`
}

// Entry is a single log entry (write or trim).
type Entry struct {
	Op          string `cbor:"1,keyasint"`
	TimestampNS uint64 `cbor:"2,keyasint"`
	Sequence    uint64 `cbor:"3,keyasint"`
	Block       uint64 `cbor:"4,keyasint"`
	Length      uint32 `cbor:"5,keyasint"`
	Checksum    uint32 `cbor:"6,keyasint,omitempty"`
	Data        []byte `cbor:"7,keyasint,omitempty"`

	CompressedSize int `cbor:"-"` // populated by Reader after LZ4 decompression
}

// IsWrite reports whether the entry is a write operation.
func (e *Entry) IsWrite() bool { return e.Op == "W" }

// IsTrim reports whether the entry is a trim/discard operation.
func (e *Entry) IsTrim() bool { return e.Op == "T" }

// ValidateCRC checks that the entry's CRC32 matches its data.
// Returns true for trim entries (which have no data or checksum).
func (e *Entry) ValidateCRC() bool {
	if e.IsTrim() {
		return true
	}
	computed := crc32.ChecksumIEEE(e.Data)
	return computed == e.Checksum
}

// Writer writes a CBOR log file as a stream of entries.
type Writer struct {
	enc *cbor.Encoder
}

// NewWriter creates a Writer that writes CBOR log entries to w.
// The header is written immediately.
func NewWriter(w io.Writer, hdr Header) (*Writer, error) {
	em, err := cbor.EncOptions{}.EncMode()
	if err != nil {
		return nil, fmt.Errorf("cbor enc mode: %w", err)
	}

	enc := em.NewEncoder(w)

	if err := enc.Encode(hdr); err != nil {
		return nil, fmt.Errorf("encode header: %w", err)
	}

	return &Writer{enc: enc}, nil
}

// WriteEntry writes a single entry. Write entry data is LZ4-compressed
// before encoding. The caller's entry is not mutated.
func (wr *Writer) WriteEntry(e *Entry) error {
	out := *e // shallow copy
	if out.IsWrite() && len(out.Data) > 0 {
		dst := make([]byte, lz4.CompressBlockBound(len(out.Data)))
		n, err := lz4.CompressBlock(out.Data, dst, nil)
		if err != nil {
			return fmt.Errorf("lz4 compress: %w", err)
		}
		out.Data = dst[:n]
	}
	if err := wr.enc.Encode(&out); err != nil {
		return fmt.Errorf("encode entry: %w", err)
	}
	return nil
}

// Reader reads a CBOR log file as a stream of entries.
type Reader struct {
	dec    *cbor.Decoder
	Header Header
}

// NewReader opens a reader on the given io.Reader, consuming the header.
func NewReader(r io.Reader) (*Reader, error) {
	dm, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		return nil, fmt.Errorf("cbor dec mode: %w", err)
	}

	dec := dm.NewDecoder(r)

	var hdr Header
	if err := dec.Decode(&hdr); err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}

	return &Reader{dec: dec, Header: hdr}, nil
}

// Next reads the next entry. Returns io.EOF when there are no more entries.
// Write entries have LZ4-compressed data which is decompressed transparently.
func (rd *Reader) Next() (*Entry, error) {
	var e Entry
	if err := rd.dec.Decode(&e); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("decode entry: %w", err)
	}

	// Decompress LZ4 data for write entries
	if e.IsWrite() && len(e.Data) > 0 && e.Length > 0 {
		e.CompressedSize = len(e.Data)
		decompressed := make([]byte, e.Length)
		n, err := lz4.UncompressBlock(e.Data, decompressed)
		if err != nil {
			return nil, fmt.Errorf("lz4 decompress: %w", err)
		}
		e.Data = decompressed[:n]
	}

	return &e, nil
}

// ReadAll reads all entries from the reader.
func (rd *Reader) ReadAll() ([]*Entry, error) {
	var entries []*Entry
	for {
		e, err := rd.Next()
		if err == io.EOF {
			return entries, nil
		}
		if err != nil {
			return entries, err
		}
		entries = append(entries, e)
	}
}
