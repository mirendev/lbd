package lbd

import (
	"sort"
	"sync"
)

// ExtentRef identifies a data source within a log file.
type ExtentRef struct {
	LogPath    string // path to log file (safe-keep copy)
	EntryIndex int    // 0-based entry index within log file
	Block      uint64 // starting block of the *original* entry
	Length     uint32 // original entry length in bytes
}

// Extent maps a contiguous block range to a log entry.
type Extent struct {
	StartBlock uint64    // first block (inclusive)
	NumBlocks  uint64    // count
	Ref        ExtentRef // data source
}

// endBlock returns the exclusive end block of the extent.
func (e Extent) endBlock() uint64 {
	return e.StartBlock + e.NumBlocks
}

// ExtentMap maintains a sorted, non-overlapping set of extents with
// a read-write mutex for concurrent access.
type ExtentMap struct {
	mu      sync.RWMutex
	extents []Extent
}

// AddWrite inserts an extent covering [block, block+numBlocks) with the
// given ref. Later writes supersede earlier ones: any existing extents
// overlapping the new range are split or removed.
func (em *ExtentMap) AddWrite(block, numBlocks uint64, ref ExtentRef) {
	em.mu.Lock()
	defer em.mu.Unlock()

	newEnd := block + numBlocks

	// Remove or split overlapping extents.
	var result []Extent
	inserted := false

	for _, ext := range em.extents {
		extEnd := ext.endBlock()

		if extEnd <= block || ext.StartBlock >= newEnd {
			// No overlap — keep as-is.
			if !inserted && ext.StartBlock >= newEnd {
				result = append(result, Extent{
					StartBlock: block,
					NumBlocks:  numBlocks,
					Ref:        ref,
				})
				inserted = true
			}
			result = append(result, ext)
			continue
		}

		// Overlap exists. Keep the portion before [block, newEnd).
		if ext.StartBlock < block {
			result = append(result, Extent{
				StartBlock: ext.StartBlock,
				NumBlocks:  block - ext.StartBlock,
				Ref:        ext.Ref,
			})
		}

		// Keep the portion after [block, newEnd).
		if extEnd > newEnd {
			result = append(result, Extent{
				StartBlock: newEnd,
				NumBlocks:  extEnd - newEnd,
				Ref:        ext.Ref,
			})
		}
	}

	if !inserted {
		// Find sorted insertion point.
		pos := sort.Search(len(result), func(i int) bool {
			return result[i].StartBlock >= block
		})
		newExtent := Extent{
			StartBlock: block,
			NumBlocks:  numBlocks,
			Ref:        ref,
		}
		result = append(result, Extent{})
		copy(result[pos+1:], result[pos:])
		result[pos] = newExtent
	}

	em.extents = result
}

// RemoveTrim removes coverage for the block range [block, block+numBlocks).
// Existing extents overlapping this range are split or removed.
func (em *ExtentMap) RemoveTrim(block, numBlocks uint64) {
	em.mu.Lock()
	defer em.mu.Unlock()

	trimEnd := block + numBlocks

	var result []Extent
	for _, ext := range em.extents {
		extEnd := ext.endBlock()

		if extEnd <= block || ext.StartBlock >= trimEnd {
			// No overlap — keep.
			result = append(result, ext)
			continue
		}

		// Keep portion before trim range.
		if ext.StartBlock < block {
			result = append(result, Extent{
				StartBlock: ext.StartBlock,
				NumBlocks:  block - ext.StartBlock,
				Ref:        ext.Ref,
			})
		}

		// Keep portion after trim range.
		if extEnd > trimEnd {
			result = append(result, Extent{
				StartBlock: trimEnd,
				NumBlocks:  extEnd - trimEnd,
				Ref:        ext.Ref,
			})
		}
	}

	em.extents = result
}

// Lookup returns all extents overlapping the range [startBlock, startBlock+numBlocks).
// The returned extents are clipped to the query range.
func (em *ExtentMap) Lookup(startBlock, numBlocks uint64) []Extent {
	em.mu.RLock()
	defer em.mu.RUnlock()

	queryEnd := startBlock + numBlocks

	var result []Extent
	for _, ext := range em.extents {
		extEnd := ext.endBlock()

		if extEnd <= startBlock {
			continue
		}
		if ext.StartBlock >= queryEnd {
			break
		}

		// Clip to query range.
		clipStart := ext.StartBlock
		if clipStart < startBlock {
			clipStart = startBlock
		}
		clipEnd := extEnd
		if clipEnd > queryEnd {
			clipEnd = queryEnd
		}

		result = append(result, Extent{
			StartBlock: clipStart,
			NumBlocks:  clipEnd - clipStart,
			Ref:        ext.Ref,
		})
	}

	return result
}

// Len returns the number of extents in the map.
func (em *ExtentMap) Len() int {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return len(em.extents)
}
