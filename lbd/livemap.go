package lbd

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/fxamacker/cbor/v2"
)

// LiveMap tracks block ownership across log segments for incremental GC.
// Extents are sorted by Start and non-overlapping. Both writes and trims
// are tracked as extents so that live trims are preserved during retirement.
type LiveMap struct {
	LastLabel string              `cbor:"1,keyasint"`
	BlockSize uint32              `cbor:"2,keyasint"`
	Extents   []LiveExtent        `cbor:"3,keyasint"`
	Segments  map[string]*SegInfo `cbor:"4,keyasint"`
}

// LiveExtent maps a contiguous block range to an owning segment.
type LiveExtent struct {
	Start   uint64 `cbor:"1,keyasint"`
	Blocks  uint64 `cbor:"2,keyasint"`
	Segment string `cbor:"3,keyasint"`
	IsTrim  bool   `cbor:"4,keyasint,omitempty"`
}

// SegInfo holds per-segment totals accumulated during log processing.
type SegInfo struct {
	TotalEntries    int    `cbor:"1,keyasint"`
	TotalWriteBytes uint64 `cbor:"2,keyasint"`
}

// NewLiveMap creates an empty LiveMap with the given block size.
func NewLiveMap(blockSize uint32) *LiveMap {
	return &LiveMap{
		BlockSize: blockSize,
		Segments:  make(map[string]*SegInfo),
	}
}

// applyOp inserts an extent covering [startBlock, startBlock+numBlocks),
// splitting or removing any overlapping existing extents.
func (lm *LiveMap) applyOp(startBlock, numBlocks uint64, segment string, isTrim bool) {
	newEnd := startBlock + numBlocks

	var result []LiveExtent
	inserted := false

	for _, ext := range lm.Extents {
		extEnd := ext.Start + ext.Blocks

		if extEnd <= startBlock || ext.Start >= newEnd {
			if !inserted && ext.Start >= newEnd {
				result = append(result, LiveExtent{
					Start:   startBlock,
					Blocks:  numBlocks,
					Segment: segment,
					IsTrim:  isTrim,
				})
				inserted = true
			}
			result = append(result, ext)
			continue
		}

		// Keep portion before the new extent.
		if ext.Start < startBlock {
			result = append(result, LiveExtent{
				Start:   ext.Start,
				Blocks:  startBlock - ext.Start,
				Segment: ext.Segment,
				IsTrim:  ext.IsTrim,
			})
		}

		// Keep portion after the new extent.
		if extEnd > newEnd {
			result = append(result, LiveExtent{
				Start:   newEnd,
				Blocks:  extEnd - newEnd,
				Segment: ext.Segment,
				IsTrim:  ext.IsTrim,
			})
		}
	}

	if !inserted {
		pos := sort.Search(len(result), func(i int) bool {
			return result[i].Start >= startBlock
		})
		newExt := LiveExtent{
			Start:   startBlock,
			Blocks:  numBlocks,
			Segment: segment,
			IsTrim:  isTrim,
		}
		result = append(result, LiveExtent{})
		copy(result[pos+1:], result[pos:])
		result[pos] = newExt
	}

	lm.Extents = result
}

// ApplyWrite records that segment owns blocks [startBlock, startBlock+numBlocks).
func (lm *LiveMap) ApplyWrite(startBlock, numBlocks uint64, segment string) {
	lm.applyOp(startBlock, numBlocks, segment, false)
}

// ApplyTrim records a trim at [startBlock, startBlock+numBlocks) owned by segment.
func (lm *LiveMap) ApplyTrim(startBlock, numBlocks uint64, segment string) {
	lm.applyOp(startBlock, numBlocks, segment, true)
}

// AddSegmentEntry increments the total counters for a segment.
func (lm *LiveMap) AddSegmentEntry(segment string, isWrite bool, writeBytes uint64) {
	seg, ok := lm.Segments[segment]
	if !ok {
		seg = &SegInfo{}
		lm.Segments[segment] = seg
	}
	seg.TotalEntries++
	if isWrite {
		seg.TotalWriteBytes += writeBytes
	}
}

// RemoveSegment removes a segment and all its extents from the map.
func (lm *LiveMap) RemoveSegment(segment string) {
	delete(lm.Segments, segment)
	var result []LiveExtent
	for _, ext := range lm.Extents {
		if ext.Segment != segment {
			result = append(result, ext)
		}
	}
	lm.Extents = result
}

// ReattributeSegment changes ownership of all extents from oldSeg to newSeg
// and merges adjacent extents with the same segment and trim status.
func (lm *LiveMap) ReattributeSegment(oldSeg, newSeg string) {
	for i := range lm.Extents {
		if lm.Extents[i].Segment == oldSeg {
			lm.Extents[i].Segment = newSeg
		}
	}
	lm.mergeAdjacent()
}

// mergeAdjacent merges adjacent extents that share the same segment and trim status.
func (lm *LiveMap) mergeAdjacent() {
	if len(lm.Extents) <= 1 {
		return
	}

	result := lm.Extents[:1]
	for i := 1; i < len(lm.Extents); i++ {
		prev := &result[len(result)-1]
		cur := lm.Extents[i]
		if prev.Segment == cur.Segment && prev.IsTrim == cur.IsTrim &&
			prev.Start+prev.Blocks == cur.Start {
			prev.Blocks += cur.Blocks
		} else {
			result = append(result, cur)
		}
	}
	lm.Extents = result
}

// SegmentLiveExtents returns all extents owned by the given segment.
func (lm *LiveMap) SegmentLiveExtents(segment string) []LiveExtent {
	var result []LiveExtent
	for _, ext := range lm.Extents {
		if ext.Segment == segment {
			result = append(result, ext)
		}
	}
	return result
}

// ComputeStats computes per-segment statistics from the live map.
func (lm *LiveMap) ComputeStats() []SegmentStats {
	liveBytes := make(map[string]uint64)
	liveCount := make(map[string]int)
	for _, ext := range lm.Extents {
		if !ext.IsTrim {
			liveBytes[ext.Segment] += ext.Blocks * uint64(lm.BlockSize)
		}
		liveCount[ext.Segment]++
	}

	var segIDs []string
	for id := range lm.Segments {
		segIDs = append(segIDs, id)
	}
	sort.Strings(segIDs)

	stats := make([]SegmentStats, len(segIDs))
	for i, id := range segIDs {
		seg := lm.Segments[id]
		stats[i] = SegmentStats{
			Path:            id,
			TotalEntries:    seg.TotalEntries,
			TotalWriteBytes: seg.TotalWriteBytes,
			LiveWriteBytes:  liveBytes[id],
			LiveEntries:     liveCount[id],
		}
	}

	return stats
}

// intersectRange returns the sub-ranges of [lo, hi) that overlap with
// the given sorted extents. Used during retirement to compute per-entry
// live ranges.
func intersectRange(extents []LiveExtent, lo, hi uint64) []Interval {
	var result []Interval
	for _, ext := range extents {
		extEnd := ext.Start + ext.Blocks
		if extEnd <= lo {
			continue
		}
		if ext.Start >= hi {
			break
		}
		start := ext.Start
		if start < lo {
			start = lo
		}
		end := extEnd
		if end > hi {
			end = hi
		}
		result = append(result, Interval{Lo: start, Hi: end})
	}
	return result
}

// MarshalLiveMap serializes a LiveMap to CBOR.
func MarshalLiveMap(lm *LiveMap) ([]byte, error) {
	return cbor.Marshal(lm)
}

// UnmarshalLiveMap deserializes a LiveMap from CBOR.
func UnmarshalLiveMap(data []byte) (*LiveMap, error) {
	var lm LiveMap
	if err := cbor.Unmarshal(data, &lm); err != nil {
		return nil, err
	}
	if lm.Segments == nil {
		lm.Segments = make(map[string]*SegInfo)
	}
	return &lm, nil
}

// LoadLiveMap reads a live map from the store. Returns nil, nil if not found.
func LoadLiveMap(ctx context.Context, store LogStore) (*LiveMap, error) {
	rc, err := store.OpenLiveMap(ctx)
	if rc == nil && err == nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening live map: %w", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("reading live map: %w", err)
	}

	return UnmarshalLiveMap(data)
}

// SaveLiveMap writes a live map to the store.
func SaveLiveMap(ctx context.Context, store LogStore, lm *LiveMap) error {
	data, err := MarshalLiveMap(lm)
	if err != nil {
		return fmt.Errorf("marshaling live map: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "lbd-livemap-*.cbor")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("writing live map: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	return store.PutLiveMap(ctx, tmpPath)
}
