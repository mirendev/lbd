// Package lbd provides qcow2-lz4 image support for reading and writing
// LBD compressed backing store images.

package lbd

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"

	"github.com/pierrec/lz4/v4"
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// On-disk format constants matching the kernel lbd_qcow2.h definitions.
const (
	QCow2Magic      = 0x4C42444351573200 // "LBDQCW2\0"
	QCow2Version    = 2
	QCow2HeaderSize = 4096
	QCow2CompLZ4    = 1

	QCow2L2Compressed = 1 << 63
	QCow2L2OffsetMask = 0x3FFFFFFFFFFFFFFF

	QCow2FreeTombstone = 0xDEADF4EE
	QCow2FreeScanLimit = 8
	QCow2FreeEntryMin  = 16
	QCow2OffFreeList   = 48

	QCow2L2TrailerSize = 8 // 4 bytes reserved + 4 bytes CRC32C at end of L2 cluster
	QCow2CompAlign     = 4096
)

// QCow2Header is the on-disk header for an LBD qcow2-lz4 image.
// All fields are big-endian on disk.
type QCow2Header struct {
	Magic           uint64
	Version         uint32
	ClusterBits     uint32
	VirtualSize     uint64
	L1TableOffset   uint64
	L1Size          uint32
	AllocOffset     uint64
	CompressionType uint32
}

// QCow2Image provides read/write access to a qcow2-lz4 image file.
type QCow2Image struct {
	f        *os.File
	readOnly bool

	ClusterBits uint32
	ClusterSize uint32
	L2Entries   uint32
	VirtualSize uint64

	L1Table   []uint64
	L1Size    uint32
	L1Offset  uint64

	AllocOffset  uint64
	FreeListHead uint64

	// In-memory L2 cache: map from L1 index to L2 table (host-endian)
	l2Cache map[uint32][]uint64
}

// CreateQCow2 creates a new empty qcow2-lz4 image file.
func CreateQCow2(path string, virtualSize uint64, clusterBits uint32) (*QCow2Image, error) {
	if clusterBits < 12 || clusterBits > 24 {
		return nil, fmt.Errorf("cluster_bits must be between 12 and 24")
	}

	clusterSize := uint32(1) << clusterBits
	l2Entries := (clusterSize - QCow2L2TrailerSize) / 8

	l1Size := uint32((virtualSize + uint64(l2Entries)*uint64(clusterSize) - 1) /
		(uint64(l2Entries) * uint64(clusterSize)))
	if l1Size == 0 {
		l1Size = 1
	}

	l1Offset := uint64(QCow2HeaderSize)
	allocOffset := l1Offset + uint64(l1Size)*8
	// Align to cluster boundary
	allocOffset = (allocOffset + uint64(clusterSize) - 1) & ^(uint64(clusterSize) - 1)

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", path, err)
	}

	// Write header
	hdr := make([]byte, QCow2HeaderSize)
	binary.BigEndian.PutUint64(hdr[0:], QCow2Magic)
	binary.BigEndian.PutUint32(hdr[8:], QCow2Version)
	binary.BigEndian.PutUint32(hdr[12:], clusterBits)
	binary.BigEndian.PutUint64(hdr[16:], virtualSize)
	binary.BigEndian.PutUint64(hdr[24:], l1Offset)
	binary.BigEndian.PutUint32(hdr[32:], l1Size)
	binary.BigEndian.PutUint64(hdr[36:], allocOffset)
	binary.BigEndian.PutUint32(hdr[44:], QCow2CompLZ4)
	binary.BigEndian.PutUint64(hdr[QCow2OffFreeList:], 0)

	if _, err := f.WriteAt(hdr, 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("write header: %w", err)
	}

	// Write zeroed L1 table
	l1Bytes := make([]byte, l1Size*8)
	if _, err := f.WriteAt(l1Bytes, int64(l1Offset)); err != nil {
		f.Close()
		return nil, fmt.Errorf("write L1 table: %w", err)
	}

	// Extend file to allocOffset
	if err := f.Truncate(int64(allocOffset)); err != nil {
		f.Close()
		return nil, fmt.Errorf("truncate: %w", err)
	}

	img := &QCow2Image{
		f:           f,
		ClusterBits: clusterBits,
		ClusterSize: clusterSize,
		L2Entries:   l2Entries,
		VirtualSize: virtualSize,
		L1Table:     make([]uint64, l1Size),
		L1Size:      l1Size,
		L1Offset:    l1Offset,
		AllocOffset: allocOffset,
		l2Cache:     make(map[uint32][]uint64),
	}

	return img, nil
}

// OpenQCow2 opens an existing qcow2-lz4 image for reading and writing.
func OpenQCow2(path string) (*QCow2Image, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	return OpenQCow2File(f)
}

// OpenQCow2ReadOnly opens an existing qcow2-lz4 image for reading only.
func OpenQCow2ReadOnly(path string) (*QCow2Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	img, err := OpenQCow2File(f)
	if err != nil {
		return nil, err
	}
	img.readOnly = true
	return img, nil
}

// OpenQCow2File opens a qcow2-lz4 image from an already-open file.
func OpenQCow2File(f *os.File) (*QCow2Image, error) {
	// Read header
	hdrBuf := make([]byte, QCow2HeaderSize)
	if _, err := f.ReadAt(hdrBuf, 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("read header: %w", err)
	}

	magic := binary.BigEndian.Uint64(hdrBuf[0:])
	if magic != QCow2Magic {
		f.Close()
		return nil, fmt.Errorf("not a qcow2-lz4 image (bad magic)")
	}

	version := binary.BigEndian.Uint32(hdrBuf[8:])
	if version != QCow2Version {
		f.Close()
		return nil, fmt.Errorf("unsupported version %d", version)
	}

	clusterBits := binary.BigEndian.Uint32(hdrBuf[12:])
	clusterSize := uint32(1) << clusterBits
	l2Entries := (clusterSize - QCow2L2TrailerSize) / 8

	img := &QCow2Image{
		f:            f,
		ClusterBits:  clusterBits,
		ClusterSize:  clusterSize,
		L2Entries:    l2Entries,
		VirtualSize:  binary.BigEndian.Uint64(hdrBuf[16:]),
		L1Offset:     binary.BigEndian.Uint64(hdrBuf[24:]),
		L1Size:       binary.BigEndian.Uint32(hdrBuf[32:]),
		AllocOffset:  binary.BigEndian.Uint64(hdrBuf[36:]),
		FreeListHead: binary.BigEndian.Uint64(hdrBuf[QCow2OffFreeList:]),
		l2Cache:      make(map[uint32][]uint64),
	}

	// Read L1 table
	img.L1Table = make([]uint64, img.L1Size)
	l1Buf := make([]byte, img.L1Size*8)
	if _, err := f.ReadAt(l1Buf, int64(img.L1Offset)); err != nil {
		f.Close()
		return nil, fmt.Errorf("read L1 table: %w", err)
	}

	for i := uint32(0); i < img.L1Size; i++ {
		img.L1Table[i] = binary.BigEndian.Uint64(l1Buf[i*8:])
	}

	return img, nil
}

// SetReadOnly marks the image as read-only, preventing writes on Close.
func (img *QCow2Image) SetReadOnly(v bool) {
	img.readOnly = v
}

// Close flushes all dirty L2 tables and the header, then closes the file.
func (img *QCow2Image) Close() error {
	if !img.readOnly {
		// Flush all cached L2 tables
		for l1Idx, l2 := range img.l2Cache {
			if err := img.writeL2Table(l1Idx, l2); err != nil {
				img.f.Close()
				return fmt.Errorf("flush L2[%d]: %w", l1Idx, err)
			}
		}

		// Write L1 table
		if err := img.writeL1Table(); err != nil {
			img.f.Close()
			return fmt.Errorf("flush L1: %w", err)
		}

		// Update alloc_offset in header
		if err := img.writeAllocOffset(); err != nil {
			img.f.Close()
			return fmt.Errorf("flush alloc_offset: %w", err)
		}
	}

	return img.f.Close()
}

// ReadCluster reads a full cluster at the given guest cluster index.
// Returns cluster_size bytes (zeros for unallocated clusters).
func (img *QCow2Image) ReadCluster(clusterIdx uint64) ([]byte, error) {
	l1Idx := uint32(clusterIdx / uint64(img.L2Entries))
	l2Idx := uint32(clusterIdx % uint64(img.L2Entries))

	if l1Idx >= img.L1Size || img.L1Table[l1Idx] == 0 {
		return make([]byte, img.ClusterSize), nil
	}

	l2, err := img.getL2(l1Idx)
	if err != nil {
		return nil, err
	}

	l2Entry := l2[l2Idx]
	if l2Entry == 0 {
		return make([]byte, img.ClusterSize), nil
	}

	physOffset := l2Entry & QCow2L2OffsetMask

	if l2Entry&QCow2L2Compressed != 0 {
		// Read compressed cluster
		var compSizeBuf [4]byte
		if _, err := img.f.ReadAt(compSizeBuf[:], int64(physOffset)); err != nil {
			return nil, fmt.Errorf("read compressed size: %w", err)
		}
		compSize := binary.BigEndian.Uint32(compSizeBuf[:])

		compData := make([]byte, compSize)
		if _, err := img.f.ReadAt(compData, int64(physOffset)+4); err != nil {
			return nil, fmt.Errorf("read compressed data: %w", err)
		}

		clusterData := make([]byte, img.ClusterSize)
		n, err := lz4.UncompressBlock(compData, clusterData)
		if err != nil {
			return nil, fmt.Errorf("LZ4 decompress: %w", err)
		}
		if uint32(n) != img.ClusterSize {
			return nil, fmt.Errorf("LZ4 decompress: got %d bytes, expected %d", n, img.ClusterSize)
		}
		return clusterData, nil
	}

	// Uncompressed cluster
	clusterData := make([]byte, img.ClusterSize)
	if _, err := img.f.ReadAt(clusterData, int64(physOffset)); err != nil {
		return nil, fmt.Errorf("read cluster: %w", err)
	}
	return clusterData, nil
}

// ReadAt reads data from the virtual address space of the image.
func (img *QCow2Image) ReadAt(buf []byte, guestOffset int64) (int, error) {
	total := 0
	remaining := len(buf)

	for remaining > 0 {
		clusterIdx := uint64(guestOffset) >> img.ClusterBits
		offInCluster := int(uint64(guestOffset) & uint64(img.ClusterSize-1))
		copyLen := int(img.ClusterSize) - offInCluster
		if copyLen > remaining {
			copyLen = remaining
		}

		clusterData, err := img.ReadCluster(clusterIdx)
		if err != nil {
			return total, err
		}

		copy(buf[total:total+copyLen], clusterData[offInCluster:offInCluster+copyLen])
		total += copyLen
		guestOffset += int64(copyLen)
		remaining -= copyLen
	}

	return total, nil
}

// WriteAt writes data to the virtual address space of the image.
// This performs read-modify-write at the cluster level, compresses, and appends.
func (img *QCow2Image) WriteAt(data []byte, guestOffset int64) (int, error) {
	total := 0
	remaining := len(data)

	for remaining > 0 {
		clusterIdx := uint64(guestOffset) >> img.ClusterBits
		offInCluster := int(uint64(guestOffset) & uint64(img.ClusterSize-1))
		writeLen := int(img.ClusterSize) - offInCluster
		if writeLen > remaining {
			writeLen = remaining
		}

		// Read existing cluster (or zeros)
		clusterData, err := img.ReadCluster(clusterIdx)
		if err != nil {
			return total, err
		}

		// Apply write
		copy(clusterData[offInCluster:], data[total:total+writeLen])

		// Compress and write cluster
		if err := img.writeCluster(clusterIdx, clusterData); err != nil {
			return total, err
		}

		total += writeLen
		guestOffset += int64(writeLen)
		remaining -= writeLen
	}

	return total, nil
}

// Trim zeroes the given range in the virtual address space.
// Full-cluster trims set the L2 entry to 0. Partial trims do read-modify-write.
func (img *QCow2Image) Trim(guestOffset int64, length int) error {
	remaining := length

	for remaining > 0 {
		clusterIdx := uint64(guestOffset) >> img.ClusterBits
		offInCluster := int(uint64(guestOffset) & uint64(img.ClusterSize-1))
		trimLen := int(img.ClusterSize) - offInCluster
		if trimLen > remaining {
			trimLen = remaining
		}

		if offInCluster == 0 && trimLen == int(img.ClusterSize) {
			// Full-cluster trim: free old extent and zero the L2 entry
			l1Idx := uint32(clusterIdx / uint64(img.L2Entries))
			l2Idx := uint32(clusterIdx % uint64(img.L2Entries))

			if l1Idx < img.L1Size && img.L1Table[l1Idx] != 0 {
				l2, err := img.getL2(l1Idx)
				if err != nil {
					return err
				}
				if l2[l2Idx] != 0 {
					oldAlloc, err := img.readOldAllocSize(l2[l2Idx])
					if err != nil {
						return err
					}
					if oldAlloc > 0 {
						oldPhys := l2[l2Idx] & QCow2L2OffsetMask
						if err := img.freeExtent(int64(oldPhys), oldAlloc); err != nil {
							return err
						}
					}
					l2[l2Idx] = 0
				}
			}
		} else {
			// Partial trim: read-modify-write
			clusterData, err := img.ReadCluster(clusterIdx)
			if err != nil {
				return err
			}

			// Check if cluster is unallocated
			l1Idx := uint32(clusterIdx / uint64(img.L2Entries))
			l2Idx := uint32(clusterIdx % uint64(img.L2Entries))
			if l1Idx < img.L1Size && img.L1Table[l1Idx] != 0 {
				l2, err := img.getL2(l1Idx)
				if err != nil {
					return err
				}
				if l2[l2Idx] == 0 {
					// Already unallocated, nothing to do
					guestOffset += int64(trimLen)
					remaining -= trimLen
					continue
				}
			} else {
				// L2 not allocated, cluster is zeros already
				guestOffset += int64(trimLen)
				remaining -= trimLen
				continue
			}

			// Zero the trimmed portion
			for i := offInCluster; i < offInCluster+trimLen; i++ {
				clusterData[i] = 0
			}

			if err := img.writeCluster(clusterIdx, clusterData); err != nil {
				return err
			}
		}

		guestOffset += int64(trimLen)
		remaining -= trimLen
	}

	return nil
}

// Flush writes all cached L2 tables and metadata to disk.
func (img *QCow2Image) Flush() error {
	for l1Idx, l2 := range img.l2Cache {
		if err := img.writeL2Table(l1Idx, l2); err != nil {
			return fmt.Errorf("flush L2[%d]: %w", l1Idx, err)
		}
	}

	if err := img.writeL1Table(); err != nil {
		return fmt.Errorf("flush L1: %w", err)
	}

	return img.writeAllocOffset()
}

// --- Internal helpers ---

// getL2 returns the L2 table for the given L1 index, loading from disk if needed.
func (img *QCow2Image) getL2(l1Idx uint32) ([]uint64, error) {
	if l2, ok := img.l2Cache[l1Idx]; ok {
		return l2, nil
	}

	l2 := make([]uint64, img.L2Entries)

	if l1Idx < img.L1Size && img.L1Table[l1Idx] != 0 {
		buf := make([]byte, img.ClusterSize)
		if _, err := img.f.ReadAt(buf, int64(img.L1Table[l1Idx])); err != nil {
			return nil, fmt.Errorf("read L2 table: %w", err)
		}

		// Verify CRC32C trailer
		storedCRC := binary.BigEndian.Uint32(buf[img.ClusterSize-4:])
		calcCRC := crc32.Checksum(buf[:img.ClusterSize-4], crc32cTable)
		if storedCRC != calcCRC {
			return nil, fmt.Errorf("L2 CRC32C mismatch for l1[%d]: stored=0x%08x computed=0x%08x",
				l1Idx, storedCRC, calcCRC)
		}

		for j := uint32(0); j < img.L2Entries; j++ {
			l2[j] = binary.BigEndian.Uint64(buf[j*8:])
		}
	}

	img.l2Cache[l1Idx] = l2
	return l2, nil
}

// allocateL2 ensures an L2 table exists for the given L1 index.
func (img *QCow2Image) allocateL2(l1Idx uint32) ([]uint64, error) {
	if l1Idx >= img.L1Size {
		return nil, fmt.Errorf("L1 index %d out of range (max %d)", l1Idx, img.L1Size-1)
	}

	if img.L1Table[l1Idx] != 0 {
		return img.getL2(l1Idx)
	}

	// Allocate L2 table at append point
	img.L1Table[l1Idx] = img.AllocOffset
	img.AllocOffset += uint64(img.ClusterSize)

	// Write zeroed L2 table with CRC32C trailer
	zeros := make([]byte, img.ClusterSize)
	crc := crc32.Checksum(zeros[:img.ClusterSize-4], crc32cTable)
	binary.BigEndian.PutUint32(zeros[img.ClusterSize-4:], crc)
	if _, err := img.f.WriteAt(zeros, int64(img.L1Table[l1Idx])); err != nil {
		return nil, fmt.Errorf("write L2 table: %w", err)
	}

	l2 := make([]uint64, img.L2Entries)
	img.l2Cache[l1Idx] = l2
	return l2, nil
}

// readOldAllocSize computes the on-disk allocation size for an existing L2 entry.
func (img *QCow2Image) readOldAllocSize(l2Entry uint64) (uint64, error) {
	if l2Entry == 0 {
		return 0, nil
	}

	if l2Entry&QCow2L2Compressed != 0 {
		physOffset := l2Entry & QCow2L2OffsetMask
		var compSizeBuf [4]byte
		if _, err := img.f.ReadAt(compSizeBuf[:], int64(physOffset)); err != nil {
			return 0, fmt.Errorf("read compressed size: %w", err)
		}
		compSize := binary.BigEndian.Uint32(compSizeBuf[:])
		return (4 + uint64(compSize) + uint64(QCow2CompAlign) - 1) & ^(uint64(QCow2CompAlign) - 1), nil
	}

	return uint64(img.ClusterSize), nil
}

// freeExtent writes a tombstone at a physical offset and prepends to the free list.
func (img *QCow2Image) freeExtent(physOffset int64, extentSize uint64) error {
	var buf [16]byte
	binary.BigEndian.PutUint32(buf[0:], QCow2FreeTombstone)
	binary.BigEndian.PutUint32(buf[4:], uint32(extentSize))
	binary.BigEndian.PutUint64(buf[8:], img.FreeListHead)

	if _, err := img.f.WriteAt(buf[:], physOffset); err != nil {
		return fmt.Errorf("write free tombstone: %w", err)
	}

	img.FreeListHead = uint64(physOffset)
	return nil
}

// allocSpace tries to find space in the free list, falls back to appending.
func (img *QCow2Image) allocSpace(needed uint64) (int64, error) {
	prevPhys := int64(0)
	cur := img.FreeListHead
	isFirst := true
	scanned := 0

	for cur != 0 && scanned < QCow2FreeScanLimit {
		var buf [16]byte
		if _, err := img.f.ReadAt(buf[:], int64(cur)); err != nil {
			break
		}

		tombstone := binary.BigEndian.Uint32(buf[0:])
		if tombstone != QCow2FreeTombstone {
			break
		}

		extentSize := uint64(binary.BigEndian.Uint32(buf[4:]))
		nextFree := binary.BigEndian.Uint64(buf[8:])

		if extentSize >= needed {
			remainder := extentSize - needed

			// Unlink this entry
			if isFirst {
				img.FreeListHead = nextFree
			} else {
				var nbuf [8]byte
				binary.BigEndian.PutUint64(nbuf[:], nextFree)
				if _, err := img.f.WriteAt(nbuf[:], prevPhys+8); err != nil {
					break // fall through to append
				}
			}

			// Split if remainder is large enough
			if remainder >= QCow2FreeEntryMin {
				splitPhys := int64(cur) + int64(needed)
				if err := img.freeExtent(splitPhys, remainder); err != nil {
					// Non-fatal: we waste the remainder
					_ = err
				}
			}

			return int64(cur), nil
		}

		prevPhys = int64(cur)
		cur = nextFree
		isFirst = false
		scanned++
	}

	// Fall back to append
	phys := img.AllocOffset
	img.AllocOffset += needed
	return int64(phys), nil
}

// writeCluster compresses and writes a full cluster, updating the L2 entry.
// Uses in-place rewrite when possible, otherwise frees the old space and allocates new.
func (img *QCow2Image) writeCluster(clusterIdx uint64, data []byte) error {
	l1Idx := uint32(clusterIdx / uint64(img.L2Entries))
	l2Idx := uint32(clusterIdx % uint64(img.L2Entries))

	// Ensure L2 table exists
	l2, err := img.allocateL2(l1Idx)
	if err != nil {
		return err
	}

	oldL2Entry := l2[l2Idx]

	var oldAlloc uint64
	if oldL2Entry != 0 {
		oldAlloc, err = img.readOldAllocSize(oldL2Entry)
		if err != nil {
			return err
		}
	}

	// Check if the data is all zeros — if so, free old extent and zero the L2 entry
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		if oldL2Entry != 0 && oldAlloc > 0 {
			oldPhys := oldL2Entry & QCow2L2OffsetMask
			if err := img.freeExtent(int64(oldPhys), oldAlloc); err != nil {
				return err
			}
		}
		l2[l2Idx] = 0
		return nil
	}

	// Try to compress
	compBound := lz4.CompressBlockBound(int(img.ClusterSize))
	compBuf := make([]byte, compBound)
	compLen, err := lz4.CompressBlock(data, compBuf, nil)
	if err != nil {
		compLen = 0 // fall back to uncompressed
	}

	if compLen > 0 && uint32(compLen) < img.ClusterSize-4 {
		// Store compressed
		newAlloc := (4 + uint64(compLen) + uint64(QCow2CompAlign) - 1) & ^(uint64(QCow2CompAlign) - 1)

		var phys int64
		if oldAlloc > 0 && newAlloc <= oldAlloc {
			phys = int64(oldL2Entry & QCow2L2OffsetMask)
		} else {
			if oldAlloc > 0 {
				if err := img.freeExtent(int64(oldL2Entry&QCow2L2OffsetMask), oldAlloc); err != nil {
					return err
				}
			}
			phys, err = img.allocSpace(newAlloc)
			if err != nil {
				return err
			}
		}

		buf := make([]byte, 4+compLen)
		binary.BigEndian.PutUint32(buf[0:], uint32(compLen))
		copy(buf[4:], compBuf[:compLen])
		if _, err := img.f.WriteAt(buf, phys); err != nil {
			return fmt.Errorf("write compressed cluster: %w", err)
		}

		l2[l2Idx] = QCow2L2Compressed | uint64(phys)
	} else {
		// Store uncompressed
		newAlloc := uint64(img.ClusterSize)

		var phys int64
		if oldAlloc > 0 && newAlloc <= oldAlloc {
			phys = int64(oldL2Entry & QCow2L2OffsetMask)
		} else {
			if oldAlloc > 0 {
				if err := img.freeExtent(int64(oldL2Entry&QCow2L2OffsetMask), oldAlloc); err != nil {
					return err
				}
			}
			phys, err = img.allocSpace(newAlloc)
			if err != nil {
				return err
			}
		}

		if _, err := img.f.WriteAt(data, phys); err != nil {
			return fmt.Errorf("write uncompressed cluster: %w", err)
		}

		l2[l2Idx] = uint64(phys)
	}

	return nil
}

// writeL2Table writes an L2 table to disk in big-endian format with CRC32C trailer.
func (img *QCow2Image) writeL2Table(l1Idx uint32, l2 []uint64) error {
	if img.L1Table[l1Idx] == 0 {
		return nil // not allocated, skip
	}

	buf := make([]byte, img.ClusterSize)
	for j := uint32(0); j < img.L2Entries; j++ {
		binary.BigEndian.PutUint64(buf[j*8:], l2[j])
	}

	// Compute CRC32C over [0, clusterSize-4) and store at end
	crc := crc32.Checksum(buf[:img.ClusterSize-4], crc32cTable)
	binary.BigEndian.PutUint32(buf[img.ClusterSize-4:], crc)

	if _, err := img.f.WriteAt(buf, int64(img.L1Table[l1Idx])); err != nil {
		return fmt.Errorf("write L2 table: %w", err)
	}
	return nil
}

// writeL1Table writes the L1 table to disk.
func (img *QCow2Image) writeL1Table() error {
	buf := make([]byte, img.L1Size*8)
	for i := uint32(0); i < img.L1Size; i++ {
		binary.BigEndian.PutUint64(buf[i*8:], img.L1Table[i])
	}

	if _, err := img.f.WriteAt(buf, int64(img.L1Offset)); err != nil {
		return fmt.Errorf("write L1 table: %w", err)
	}
	return nil
}

// writeAllocOffset updates the alloc_offset and free_list_head fields in the on-disk header.
func (img *QCow2Image) writeAllocOffset() error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], img.AllocOffset)

	// alloc_offset is at offset 36 in the header
	if _, err := img.f.WriteAt(buf[:], 36); err != nil {
		return fmt.Errorf("write alloc_offset: %w", err)
	}

	binary.BigEndian.PutUint64(buf[:], img.FreeListHead)
	if _, err := img.f.WriteAt(buf[:], QCow2OffFreeList); err != nil {
		return fmt.Errorf("write free_list_head: %w", err)
	}
	return nil
}

// ExtractTo extracts the full virtual contents of the image to a flat file.
func (img *QCow2Image) ExtractTo(w io.WriterAt, size int64) error {
	totalClusters := (uint64(size) + uint64(img.ClusterSize) - 1) / uint64(img.ClusterSize)

	for ci := uint64(0); ci < totalClusters; ci++ {
		clusterData, err := img.ReadCluster(ci)
		if err != nil {
			return fmt.Errorf("read cluster %d: %w", ci, err)
		}

		writeLen := int(img.ClusterSize)
		if (ci+1)*uint64(img.ClusterSize) > uint64(size) {
			writeLen = int(uint64(size) - ci*uint64(img.ClusterSize))
		}

		if _, err := w.WriteAt(clusterData[:writeLen], int64(ci)*int64(img.ClusterSize)); err != nil {
			return fmt.Errorf("write cluster %d: %w", ci, err)
		}
	}

	return nil
}
