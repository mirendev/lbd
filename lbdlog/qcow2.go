// Package lbdlog provides qcow2-lz4 image support for reading and writing
// LBD compressed backing store images.

package lbdlog

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pierrec/lz4/v4"
)

// On-disk format constants matching the kernel lbd_qcow2.h definitions.
const (
	QCow2Magic      = 0x4C42444351573200 // "LBDQCW2\0"
	QCow2Version    = 1
	QCow2HeaderSize = 4096
	QCow2CompLZ4    = 1

	QCow2L2Compressed = 1 << 63
	QCow2L2COW        = 1 << 62
	QCow2L2OffsetMask = 0x3FFFFFFFFFFFFFFF

	QCow2FreeTombstone  = 0xDEADF4EE
	QCow2FreeScanLimit  = 8
	QCow2FreeEntryMin   = 16
	QCow2OffFreeList    = 48

	QCow2OffIncompatFeat      = 56
	QCow2OffRefcountTable     = 64
	QCow2OffRefcountClusters  = 72
	QCow2OffSnapshotTable     = 76
	QCow2OffSnapshotCount     = 84

	QCow2FeatRefcounts = uint64(1) << 0
	QCow2FeatSnapshots = uint64(1) << 1

	QCow2SnapFixedSize = 26
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

// SnapshotEntry represents an in-memory snapshot table entry.
type SnapshotEntry struct {
	ID       uint32
	L1Offset uint64
	L1Size   uint32
	DateSec  uint32
	DateNsec uint32
	Name     string
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

	// Refcount tracking
	IncompatFeatures uint64
	refcounts        map[uint64]uint16 // host cluster index -> refcount
	hasRefcounts     bool

	// Snapshot metadata
	Snapshots      []SnapshotEntry
	SnapshotCount  uint32
	NextSnapshotID uint32
}

// CreateQCow2 creates a new empty qcow2-lz4 image file.
func CreateQCow2(path string, virtualSize uint64, clusterBits uint32) (*QCow2Image, error) {
	if clusterBits < 12 || clusterBits > 24 {
		return nil, fmt.Errorf("cluster_bits must be between 12 and 24")
	}

	clusterSize := uint32(1) << clusterBits
	l2Entries := clusterSize / 8

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
	l2Entries := clusterSize / 8

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

	// Load incompatible features and snapshot/refcount metadata
	img.IncompatFeatures = binary.BigEndian.Uint64(hdrBuf[QCow2OffIncompatFeat:])

	if img.IncompatFeatures&QCow2FeatRefcounts != 0 {
		refTableOffset := binary.BigEndian.Uint64(hdrBuf[QCow2OffRefcountTable:])
		refTableClusters := binary.BigEndian.Uint32(hdrBuf[QCow2OffRefcountClusters:])

		img.refcounts = make(map[uint64]uint16)
		img.hasRefcounts = true

		entriesPerBlock := uint64(img.ClusterSize) / 2

		tableBuf := make([]byte, refTableClusters*8)
		if _, err := f.ReadAt(tableBuf, int64(refTableOffset)); err != nil {
			f.Close()
			return nil, fmt.Errorf("read refcount table: %w", err)
		}

		for bi := uint32(0); bi < refTableClusters; bi++ {
			blockOffset := binary.BigEndian.Uint64(tableBuf[bi*8:])
			if blockOffset == 0 {
				continue
			}

			blockBuf := make([]byte, img.ClusterSize)
			if _, err := f.ReadAt(blockBuf, int64(blockOffset)); err != nil {
				f.Close()
				return nil, fmt.Errorf("read refcount block %d: %w", bi, err)
			}

			blockStart := uint64(bi) * entriesPerBlock
			for j := uint64(0); j < entriesPerBlock; j++ {
				rc := binary.BigEndian.Uint16(blockBuf[j*2:])
				if rc > 0 {
					img.refcounts[blockStart+j] = rc
				}
			}
		}
	}

	if img.IncompatFeatures&QCow2FeatSnapshots != 0 {
		snapTableOffset := binary.BigEndian.Uint64(hdrBuf[QCow2OffSnapshotTable:])
		snapCount := binary.BigEndian.Uint32(hdrBuf[QCow2OffSnapshotCount:])

		// Read snapshot table entries
		snapBufSize := uint64(snapCount) * 288
		if snapBufSize < uint64(img.ClusterSize) {
			snapBufSize = uint64(img.ClusterSize)
		}
		snapBuf := make([]byte, snapBufSize)
		n, _ := f.ReadAt(snapBuf, int64(snapTableOffset))
		snapBuf = snapBuf[:n]

		off := 0
		img.Snapshots = make([]SnapshotEntry, 0, snapCount)
		for i := uint32(0); i < snapCount && off+QCow2SnapFixedSize <= len(snapBuf); i++ {
			snap := SnapshotEntry{
				ID:       binary.BigEndian.Uint32(snapBuf[off:]),
				L1Offset: binary.BigEndian.Uint64(snapBuf[off+4:]),
				L1Size:   binary.BigEndian.Uint32(snapBuf[off+12:]),
				DateSec:  binary.BigEndian.Uint32(snapBuf[off+16:]),
				DateNsec: binary.BigEndian.Uint32(snapBuf[off+20:]),
			}
			nameLen := binary.BigEndian.Uint16(snapBuf[off+24:])
			off += QCow2SnapFixedSize
			if off+int(nameLen) > len(snapBuf) {
				break
			}
			snap.Name = string(snapBuf[off : off+int(nameLen)])
			off += int(nameLen)
			if off%8 != 0 {
				off += 8 - (off % 8)
			}
			img.Snapshots = append(img.Snapshots, snap)
			if snap.ID >= img.NextSnapshotID {
				img.NextSnapshotID = snap.ID + 1
			}
		}
		img.SnapshotCount = uint32(len(img.Snapshots))
	}

	return img, nil
}

// SetReadOnly marks the image as read-only, preventing writes on Close.
func (img *QCow2Image) SetReadOnly(v bool) {
	img.readOnly = v
}

// Close flushes all dirty L2 tables, refcount/snapshot metadata, and the header,
// then closes the file.
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

		// Write snapshot and refcount metadata (may allocate space)
		if img.hasRefcounts {
			if err := img.writeSnapshotTable(); err != nil {
				img.f.Close()
				return fmt.Errorf("flush snapshots: %w", err)
			}
			if err := img.flushRefcounts(); err != nil {
				img.f.Close()
				return fmt.Errorf("flush refcounts: %w", err)
			}
			if err := img.writeIncompatFeatures(); err != nil {
				img.f.Close()
				return fmt.Errorf("flush features: %w", err)
			}
		}

		// Update alloc_offset in header (after all allocations)
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
				if err := img.cowL2IfNeeded(l1Idx); err != nil {
					return err
				}
				l2, err := img.getL2(l1Idx)
				if err != nil {
					return err
				}
				if l2[l2Idx] != 0 {
					if l2[l2Idx]&QCow2L2COW == 0 {
						// Not COW: free old extent
						oldAlloc, err := img.readOldAllocSize(l2[l2Idx])
						if err != nil {
							return err
						}
						if oldAlloc > 0 {
							oldPhys := l2[l2Idx] & QCow2L2OffsetMask
							if err := img.freeWithRefcount(oldPhys, oldAlloc); err != nil {
								return err
							}
						}
					}
					// COW or not: zero the L2 entry
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
	img.incrementRefcount(img.L1Table[l1Idx], uint64(img.ClusterSize))

	// Write zeroed L2 table
	zeros := make([]byte, img.ClusterSize)
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
// Handles COW flag: if the old L2 entry is shared with a snapshot, new space is
// always allocated and the old allocation is not freed.
func (img *QCow2Image) writeCluster(clusterIdx uint64, data []byte) error {
	l1Idx := uint32(clusterIdx / uint64(img.L2Entries))
	l2Idx := uint32(clusterIdx % uint64(img.L2Entries))

	// COW the L2 table itself if it's shared with a snapshot
	if err := img.cowL2IfNeeded(l1Idx); err != nil {
		return err
	}

	// Ensure L2 table exists
	l2, err := img.allocateL2(l1Idx)
	if err != nil {
		return err
	}

	oldL2Entry := l2[l2Idx]
	mustCOW := oldL2Entry&QCow2L2COW != 0

	// For non-COW entries, get old allocation size for potential reuse
	var oldAlloc uint64
	if oldL2Entry != 0 && !mustCOW {
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
		if oldL2Entry != 0 && !mustCOW && oldAlloc > 0 {
			oldPhys := oldL2Entry & QCow2L2OffsetMask
			if err := img.freeWithRefcount(oldPhys, oldAlloc); err != nil {
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
		phys, err := img.allocForWrite(oldL2Entry, mustCOW, oldAlloc, newAlloc)
		if err != nil {
			return err
		}

		// Write size header + compressed data
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
		phys, err := img.allocForWrite(oldL2Entry, mustCOW, oldAlloc, newAlloc)
		if err != nil {
			return err
		}

		if _, err := img.f.WriteAt(data, phys); err != nil {
			return fmt.Errorf("write uncompressed cluster: %w", err)
		}

		l2[l2Idx] = uint64(phys)
	}

	return nil
}

// allocForWrite handles the allocation decision for a write, considering COW and refcounts.
func (img *QCow2Image) allocForWrite(oldL2Entry uint64, mustCOW bool, oldAlloc, newAlloc uint64) (int64, error) {
	if mustCOW {
		// Shared with snapshot — must allocate new, don't free old
		phys, err := img.allocSpace(newAlloc)
		if err != nil {
			return 0, err
		}
		img.incrementRefcount(uint64(phys), newAlloc)
		return phys, nil
	}

	if oldAlloc > 0 && newAlloc <= oldAlloc {
		// In-place rewrite
		return int64(oldL2Entry & QCow2L2OffsetMask), nil
	}

	// Free old extent if it exists
	if oldAlloc > 0 {
		oldPhys := oldL2Entry & QCow2L2OffsetMask
		if err := img.freeWithRefcount(oldPhys, oldAlloc); err != nil {
			return 0, err
		}
	}

	// Allocate new space
	phys, err := img.allocSpace(newAlloc)
	if err != nil {
		return 0, err
	}
	img.incrementRefcount(uint64(phys), newAlloc)
	return phys, nil
}

// writeL2Table writes an L2 table to disk in big-endian format.
func (img *QCow2Image) writeL2Table(l1Idx uint32, l2 []uint64) error {
	if img.L1Table[l1Idx] == 0 {
		return nil // not allocated, skip
	}

	buf := make([]byte, img.ClusterSize)
	for j := uint32(0); j < img.L2Entries; j++ {
		binary.BigEndian.PutUint64(buf[j*8:], l2[j])
	}

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

// --- Refcount tracking ---

// incrementRefcount bumps the refcount for each host cluster spanned by the allocation.
func (img *QCow2Image) incrementRefcount(physOffset uint64, allocSize uint64) {
	if !img.hasRefcounts {
		return
	}
	startCluster := physOffset / uint64(img.ClusterSize)
	endCluster := (physOffset + allocSize - 1) / uint64(img.ClusterSize)
	for c := startCluster; c <= endCluster; c++ {
		img.refcounts[c]++
	}
}

// decrementRefcount decreases the refcount for each host cluster spanned by the allocation.
func (img *QCow2Image) decrementRefcount(physOffset uint64, allocSize uint64) {
	if !img.hasRefcounts {
		return
	}
	startCluster := physOffset / uint64(img.ClusterSize)
	endCluster := (physOffset + allocSize - 1) / uint64(img.ClusterSize)
	for c := startCluster; c <= endCluster; c++ {
		rc := img.refcounts[c]
		if rc > 1 {
			img.refcounts[c] = rc - 1
		} else if rc == 1 {
			delete(img.refcounts, c)
		}
	}
}

// freeWithRefcount decrements refcounts and only adds a tombstone if all spanned
// host clusters reached refcount 0.
func (img *QCow2Image) freeWithRefcount(physOffset uint64, allocSize uint64) error {
	if !img.hasRefcounts {
		return img.freeExtent(int64(physOffset), allocSize)
	}

	startCluster := physOffset / uint64(img.ClusterSize)
	endCluster := (physOffset + allocSize - 1) / uint64(img.ClusterSize)

	// First pass: check if all would reach 0
	canFree := true
	for c := startCluster; c <= endCluster; c++ {
		if img.refcounts[c] > 1 {
			canFree = false
			break
		}
	}

	// Second pass: decrement
	for c := startCluster; c <= endCluster; c++ {
		rc := img.refcounts[c]
		if rc > 1 {
			img.refcounts[c] = rc - 1
		} else if rc == 1 {
			delete(img.refcounts, c)
		}
	}

	if canFree {
		return img.freeExtent(int64(physOffset), allocSize)
	}
	return nil
}

// initRefcountsFromScan walks all L1/L2 tables to build the initial refcount map.
func (img *QCow2Image) initRefcountsFromScan() {
	img.refcounts = make(map[uint64]uint16)

	// Count references from L2 table clusters
	for i := uint32(0); i < img.L1Size; i++ {
		if img.L1Table[i] == 0 {
			continue
		}
		l2Phys := img.L1Table[i]
		startC := l2Phys / uint64(img.ClusterSize)
		endC := (l2Phys + uint64(img.ClusterSize) - 1) / uint64(img.ClusterSize)
		for c := startC; c <= endC; c++ {
			img.refcounts[c]++
		}
	}

	// Count references from data clusters
	for i := uint32(0); i < img.L1Size; i++ {
		if img.L1Table[i] == 0 {
			continue
		}
		l2, err := img.getL2(i)
		if err != nil {
			continue
		}
		for j := uint32(0); j < img.L2Entries; j++ {
			entry := l2[j]
			if entry == 0 {
				continue
			}
			physOffset := entry & QCow2L2OffsetMask
			if entry&QCow2L2Compressed != 0 {
				allocSize, err := img.readOldAllocSize(entry)
				if err != nil {
					continue
				}
				startC := physOffset / uint64(img.ClusterSize)
				endC := (physOffset + allocSize - 1) / uint64(img.ClusterSize)
				for c := startC; c <= endC; c++ {
					img.refcounts[c]++
				}
			} else {
				startC := physOffset / uint64(img.ClusterSize)
				endC := (physOffset + uint64(img.ClusterSize) - 1) / uint64(img.ClusterSize)
				for c := startC; c <= endC; c++ {
					img.refcounts[c]++
				}
			}
		}
	}

	img.hasRefcounts = true
}

// --- L2 COW ---

// cowL2IfNeeded checks if the L2 table at l1Idx is shared with a snapshot
// (refcount > 1) and if so, creates a private copy for the active image.
func (img *QCow2Image) cowL2IfNeeded(l1Idx uint32) error {
	if !img.hasRefcounts || l1Idx >= img.L1Size {
		return nil
	}

	l2Phys := img.L1Table[l1Idx]
	if l2Phys == 0 {
		return nil
	}

	hostCluster := l2Phys / uint64(img.ClusterSize)
	rc := img.refcounts[hostCluster]
	if rc <= 1 {
		return nil // not shared
	}

	// Read the old L2 table
	oldBuf := make([]byte, img.ClusterSize)
	if _, err := img.f.ReadAt(oldBuf, int64(l2Phys)); err != nil {
		return fmt.Errorf("read L2 for COW: %w", err)
	}

	// Allocate new space for L2 table
	newPhys := img.AllocOffset
	img.AllocOffset += uint64(img.ClusterSize)

	// Write copy
	if _, err := img.f.WriteAt(oldBuf, int64(newPhys)); err != nil {
		return fmt.Errorf("write COW L2: %w", err)
	}

	// Update L1 table
	img.L1Table[l1Idx] = newPhys

	// Update refcounts: decrement old, increment new
	if rc > 1 {
		img.refcounts[hostCluster] = rc - 1
	} else {
		delete(img.refcounts, hostCluster)
	}
	newHostCluster := newPhys / uint64(img.ClusterSize)
	img.refcounts[newHostCluster]++

	// Invalidate L2 cache (will be re-read from new location)
	delete(img.l2Cache, l1Idx)

	return nil
}

// --- Snapshots ---

// SnapshotCreate creates a named internal snapshot of the current image state.
func (img *QCow2Image) SnapshotCreate(name string) error {
	// 1. Flush all L2 cache to disk
	for l1Idx, l2 := range img.l2Cache {
		if err := img.writeL2Table(l1Idx, l2); err != nil {
			return fmt.Errorf("flush L2[%d]: %w", l1Idx, err)
		}
	}

	// 2. Write L1 table to disk
	if err := img.writeL1Table(); err != nil {
		return fmt.Errorf("flush L1: %w", err)
	}

	// 3. Allocate space for L1 table copy
	l1CopySize := uint64(img.L1Size) * 8
	l1CopySize = (l1CopySize + uint64(img.ClusterSize) - 1) & ^(uint64(img.ClusterSize) - 1)
	l1CopyOffset := img.AllocOffset
	img.AllocOffset += l1CopySize

	// 4. Write L1 table copy
	l1Buf := make([]byte, img.L1Size*8)
	for i := uint32(0); i < img.L1Size; i++ {
		binary.BigEndian.PutUint64(l1Buf[i*8:], img.L1Table[i])
	}
	if _, err := img.f.WriteAt(l1Buf, int64(l1CopyOffset)); err != nil {
		return fmt.Errorf("write L1 copy: %w", err)
	}

	// 5. Initialize or update refcounts
	if !img.hasRefcounts {
		img.initRefcountsFromScan()
	}

	// Increment refcounts for all clusters referenced by active L2 tables
	// (the snapshot now shares these references)
	for i := uint32(0); i < img.L1Size; i++ {
		if img.L1Table[i] == 0 {
			continue
		}
		// Increment for L2 table cluster
		img.incrementRefcount(img.L1Table[i], uint64(img.ClusterSize))

		l2, err := img.getL2(i)
		if err != nil {
			return err
		}
		for j := uint32(0); j < img.L2Entries; j++ {
			entry := l2[j]
			if entry == 0 {
				continue
			}
			physOffset := entry & QCow2L2OffsetMask
			if entry&QCow2L2Compressed != 0 {
				allocSize, err := img.readOldAllocSize(entry)
				if err != nil {
					continue
				}
				img.incrementRefcount(physOffset, allocSize)
			} else {
				img.incrementRefcount(physOffset, uint64(img.ClusterSize))
			}
		}
	}
	// Increment for L1 copy itself
	img.incrementRefcount(l1CopyOffset, l1CopySize)

	// 6. Set COW flag on all non-zero L2 entries
	for i := uint32(0); i < img.L1Size; i++ {
		if img.L1Table[i] == 0 {
			continue
		}
		l2, err := img.getL2(i)
		if err != nil {
			return err
		}
		changed := false
		for j := uint32(0); j < img.L2Entries; j++ {
			if l2[j] != 0 && l2[j]&QCow2L2COW == 0 {
				l2[j] |= QCow2L2COW
				changed = true
			}
		}
		if changed {
			if err := img.writeL2Table(i, l2); err != nil {
				return fmt.Errorf("flush L2[%d] with COW: %w", i, err)
			}
		}
	}

	// 7. Create snapshot entry
	now := time.Now()
	snap := SnapshotEntry{
		ID:       img.NextSnapshotID,
		L1Offset: l1CopyOffset,
		L1Size:   img.L1Size,
		DateSec:  uint32(now.Unix()),
		DateNsec: uint32(now.Nanosecond()),
		Name:     name,
	}
	img.NextSnapshotID++
	img.Snapshots = append(img.Snapshots, snap)
	img.SnapshotCount = uint32(len(img.Snapshots))

	// 8. Update incompatible features
	img.IncompatFeatures |= QCow2FeatRefcounts | QCow2FeatSnapshots

	// 9. Persist alloc offset (new allocations happened)
	if err := img.writeAllocOffset(); err != nil {
		return fmt.Errorf("flush alloc_offset: %w", err)
	}

	return nil
}

// SnapshotDelete removes a snapshot by ID, decrementing refcounts for its clusters.
func (img *QCow2Image) SnapshotDelete(id uint32) error {
	// Find snapshot
	snapIdx := -1
	for i, s := range img.Snapshots {
		if s.ID == id {
			snapIdx = i
			break
		}
	}
	if snapIdx < 0 {
		return fmt.Errorf("snapshot %d not found", id)
	}

	snap := img.Snapshots[snapIdx]

	// Load snapshot's L1 table
	snapL1 := make([]uint64, snap.L1Size)
	l1Buf := make([]byte, snap.L1Size*8)
	if _, err := img.f.ReadAt(l1Buf, int64(snap.L1Offset)); err != nil {
		return fmt.Errorf("read snapshot L1: %w", err)
	}
	for i := uint32(0); i < snap.L1Size; i++ {
		snapL1[i] = binary.BigEndian.Uint64(l1Buf[i*8:])
	}

	// Walk snapshot's L2 tables and decrement refcounts
	for i := uint32(0); i < snap.L1Size; i++ {
		if snapL1[i] == 0 {
			continue
		}

		// Read snapshot's L2 table
		l2Buf := make([]byte, img.ClusterSize)
		if _, err := img.f.ReadAt(l2Buf, int64(snapL1[i])); err != nil {
			return fmt.Errorf("read snapshot L2[%d]: %w", i, err)
		}

		for j := uint32(0); j < img.L2Entries; j++ {
			entry := binary.BigEndian.Uint64(l2Buf[j*8:])
			if entry == 0 {
				continue
			}
			physOffset := entry & QCow2L2OffsetMask
			if entry&QCow2L2Compressed != 0 {
				allocSize, err := img.readOldAllocSize(entry)
				if err != nil {
					continue
				}
				img.decrementRefcount(physOffset, allocSize)
			} else {
				img.decrementRefcount(physOffset, uint64(img.ClusterSize))
			}
		}

		// Decrement refcount for L2 table cluster
		img.decrementRefcount(snapL1[i], uint64(img.ClusterSize))
	}

	// Free snapshot's L1 table
	l1AllocSize := uint64(snap.L1Size) * 8
	l1AllocSize = (l1AllocSize + uint64(img.ClusterSize) - 1) & ^(uint64(img.ClusterSize) - 1)
	img.decrementRefcount(snap.L1Offset, l1AllocSize)

	// Remove snapshot from list
	img.Snapshots = append(img.Snapshots[:snapIdx], img.Snapshots[snapIdx+1:]...)
	img.SnapshotCount = uint32(len(img.Snapshots))

	// If no snapshots remain, clear COW flags on all active L2 entries
	if img.SnapshotCount == 0 {
		for i := uint32(0); i < img.L1Size; i++ {
			if img.L1Table[i] == 0 {
				continue
			}
			l2, err := img.getL2(i)
			if err != nil {
				continue
			}
			for j := uint32(0); j < img.L2Entries; j++ {
				l2[j] &^= QCow2L2COW
			}
			if err := img.writeL2Table(i, l2); err != nil {
				return err
			}
		}
	}

	return nil
}

// --- On-disk persistence of refcounts and snapshots ---

// flushRefcounts writes the two-level refcount table to disk.
func (img *QCow2Image) flushRefcounts() error {
	if !img.hasRefcounts {
		return nil
	}

	entriesPerBlock := uint64(img.ClusterSize) / 2

	// Find max host cluster index
	var maxCluster uint64
	for c := range img.refcounts {
		if c > maxCluster {
			maxCluster = c
		}
	}

	if len(img.refcounts) == 0 {
		// No refcounts to write, but still update header to clear
		var buf [4]byte
		if _, err := img.f.WriteAt(buf[:], QCow2OffRefcountClusters); err != nil {
			return err
		}
		return nil
	}

	numBlocks := (maxCluster + entriesPerBlock) / entriesPerBlock
	if numBlocks == 0 {
		numBlocks = 1
	}

	// Allocate refcount table
	tableSize := numBlocks * 8
	tableSize = (tableSize + uint64(img.ClusterSize) - 1) & ^(uint64(img.ClusterSize) - 1)
	tableOffset := img.AllocOffset
	img.AllocOffset += tableSize

	refcountTable := make([]byte, tableSize)

	// For each block that has non-zero entries
	for bi := uint64(0); bi < numBlocks; bi++ {
		blockStart := bi * entriesPerBlock
		blockEnd := blockStart + entriesPerBlock

		hasEntries := false
		for c := blockStart; c < blockEnd; c++ {
			if img.refcounts[c] > 0 {
				hasEntries = true
				break
			}
		}
		if !hasEntries {
			continue
		}

		// Allocate cluster for this block
		blockOffset := img.AllocOffset
		img.AllocOffset += uint64(img.ClusterSize)

		// Fill entries
		blockBuf := make([]byte, img.ClusterSize)
		for c := blockStart; c < blockEnd; c++ {
			rc := img.refcounts[c]
			if rc > 0 {
				idx := (c - blockStart) * 2
				binary.BigEndian.PutUint16(blockBuf[idx:], rc)
			}
		}

		// Write block
		if _, err := img.f.WriteAt(blockBuf, int64(blockOffset)); err != nil {
			return fmt.Errorf("write refcount block %d: %w", bi, err)
		}

		// Store pointer in table
		binary.BigEndian.PutUint64(refcountTable[bi*8:], blockOffset)
	}

	// Write refcount table
	if _, err := img.f.WriteAt(refcountTable, int64(tableOffset)); err != nil {
		return fmt.Errorf("write refcount table: %w", err)
	}

	// Update header
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], tableOffset)
	if _, err := img.f.WriteAt(buf[:], QCow2OffRefcountTable); err != nil {
		return err
	}

	binary.BigEndian.PutUint32(buf[:4], uint32(numBlocks))
	if _, err := img.f.WriteAt(buf[:4], QCow2OffRefcountClusters); err != nil {
		return err
	}

	return nil
}

// writeSnapshotTable writes the snapshot table to disk.
func (img *QCow2Image) writeSnapshotTable() error {
	if len(img.Snapshots) == 0 {
		var buf [12]byte
		if _, err := img.f.WriteAt(buf[:8], QCow2OffSnapshotTable); err != nil {
			return err
		}
		if _, err := img.f.WriteAt(buf[:4], QCow2OffSnapshotCount); err != nil {
			return err
		}
		return nil
	}

	// Compute total size
	totalSize := uint64(0)
	for _, s := range img.Snapshots {
		entrySize := uint64(QCow2SnapFixedSize) + uint64(len(s.Name))
		entrySize = (entrySize + 7) & ^uint64(7) // 8-byte align
		totalSize += entrySize
	}
	totalSize = (totalSize + uint64(img.ClusterSize) - 1) & ^(uint64(img.ClusterSize) - 1)

	// Allocate space
	tableOffset := img.AllocOffset
	img.AllocOffset += totalSize

	// Write entries
	buf := make([]byte, totalSize)
	off := 0
	for _, s := range img.Snapshots {
		binary.BigEndian.PutUint32(buf[off:], s.ID)
		off += 4
		binary.BigEndian.PutUint64(buf[off:], s.L1Offset)
		off += 8
		binary.BigEndian.PutUint32(buf[off:], s.L1Size)
		off += 4
		binary.BigEndian.PutUint32(buf[off:], s.DateSec)
		off += 4
		binary.BigEndian.PutUint32(buf[off:], s.DateNsec)
		off += 4
		binary.BigEndian.PutUint16(buf[off:], uint16(len(s.Name)))
		off += 2
		copy(buf[off:], s.Name)
		off += len(s.Name)
		if off%8 != 0 {
			off += 8 - (off % 8)
		}
	}

	if _, err := img.f.WriteAt(buf, int64(tableOffset)); err != nil {
		return fmt.Errorf("write snapshot table: %w", err)
	}

	// Update header
	var hbuf [8]byte
	binary.BigEndian.PutUint64(hbuf[:], tableOffset)
	if _, err := img.f.WriteAt(hbuf[:], QCow2OffSnapshotTable); err != nil {
		return err
	}

	binary.BigEndian.PutUint32(hbuf[:4], uint32(len(img.Snapshots)))
	if _, err := img.f.WriteAt(hbuf[:4], QCow2OffSnapshotCount); err != nil {
		return err
	}

	return nil
}

// writeIncompatFeatures writes the incompatible_features field to the header.
func (img *QCow2Image) writeIncompatFeatures() error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], img.IncompatFeatures)
	if _, err := img.f.WriteAt(buf[:], QCow2OffIncompatFeat); err != nil {
		return fmt.Errorf("write incompatible_features: %w", err)
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
