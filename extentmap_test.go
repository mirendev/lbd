package lbd

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ref(path string, idx int, block uint64, length uint32) ExtentRef {
	return ExtentRef{
		LogPath:    path,
		EntryIndex: idx,
		Block:      block,
		Length:     length,
	}
}

func TestExtentMapDisjointWrites(t *testing.T) {
	var em ExtentMap

	r1 := ref("log1", 0, 0, 4096)
	r2 := ref("log1", 1, 10, 4096)

	em.AddWrite(0, 1, r1)
	em.AddWrite(10, 1, r2)

	assert.Equal(t, 2, em.Len())

	extents := em.Lookup(0, 20)
	require.Len(t, extents, 2)
	assert.Equal(t, uint64(0), extents[0].StartBlock)
	assert.Equal(t, uint64(1), extents[0].NumBlocks)
	assert.Equal(t, r1, extents[0].Ref)
	assert.Equal(t, uint64(10), extents[1].StartBlock)
	assert.Equal(t, uint64(1), extents[1].NumBlocks)
	assert.Equal(t, r2, extents[1].Ref)
}

func TestExtentMapOverwriteStart(t *testing.T) {
	// Original: blocks 0-4 (ref A)
	// New write: block 0 (ref B)
	// Result: block 0 (ref B), blocks 1-4 (ref A)
	var em ExtentMap

	refA := ref("log1", 0, 0, 5*4096)
	refB := ref("log2", 0, 0, 4096)

	em.AddWrite(0, 5, refA)
	em.AddWrite(0, 1, refB)

	assert.Equal(t, 2, em.Len())

	extents := em.Lookup(0, 5)
	require.Len(t, extents, 2)

	assert.Equal(t, uint64(0), extents[0].StartBlock)
	assert.Equal(t, uint64(1), extents[0].NumBlocks)
	assert.Equal(t, refB, extents[0].Ref)

	assert.Equal(t, uint64(1), extents[1].StartBlock)
	assert.Equal(t, uint64(4), extents[1].NumBlocks)
	assert.Equal(t, refA, extents[1].Ref)
}

func TestExtentMapOverwriteEnd(t *testing.T) {
	// Original: blocks 0-4 (ref A)
	// New write: block 4 (ref B)
	// Result: blocks 0-3 (ref A), block 4 (ref B)
	var em ExtentMap

	refA := ref("log1", 0, 0, 5*4096)
	refB := ref("log2", 0, 4, 4096)

	em.AddWrite(0, 5, refA)
	em.AddWrite(4, 1, refB)

	assert.Equal(t, 2, em.Len())

	extents := em.Lookup(0, 5)
	require.Len(t, extents, 2)

	assert.Equal(t, uint64(0), extents[0].StartBlock)
	assert.Equal(t, uint64(4), extents[0].NumBlocks)
	assert.Equal(t, refA, extents[0].Ref)

	assert.Equal(t, uint64(4), extents[1].StartBlock)
	assert.Equal(t, uint64(1), extents[1].NumBlocks)
	assert.Equal(t, refB, extents[1].Ref)
}

func TestExtentMapOverwriteMiddle(t *testing.T) {
	// Original: blocks 0-4 (ref A)
	// New write: block 2 (ref B)
	// Result: blocks 0-1 (ref A), block 2 (ref B), blocks 3-4 (ref A)
	var em ExtentMap

	refA := ref("log1", 0, 0, 5*4096)
	refB := ref("log2", 0, 2, 4096)

	em.AddWrite(0, 5, refA)
	em.AddWrite(2, 1, refB)

	assert.Equal(t, 3, em.Len())

	extents := em.Lookup(0, 5)
	require.Len(t, extents, 3)

	assert.Equal(t, uint64(0), extents[0].StartBlock)
	assert.Equal(t, uint64(2), extents[0].NumBlocks)
	assert.Equal(t, refA, extents[0].Ref)

	assert.Equal(t, uint64(2), extents[1].StartBlock)
	assert.Equal(t, uint64(1), extents[1].NumBlocks)
	assert.Equal(t, refB, extents[1].Ref)

	assert.Equal(t, uint64(3), extents[2].StartBlock)
	assert.Equal(t, uint64(2), extents[2].NumBlocks)
	assert.Equal(t, refA, extents[2].Ref)
}

func TestExtentMapFullOverwrite(t *testing.T) {
	var em ExtentMap

	refA := ref("log1", 0, 0, 5*4096)
	refB := ref("log2", 0, 0, 5*4096)

	em.AddWrite(0, 5, refA)
	em.AddWrite(0, 5, refB)

	assert.Equal(t, 1, em.Len())

	extents := em.Lookup(0, 5)
	require.Len(t, extents, 1)
	assert.Equal(t, refB, extents[0].Ref)
}

func TestExtentMapSupersetOverwrite(t *testing.T) {
	var em ExtentMap

	refA := ref("log1", 0, 2, 2*4096)
	refB := ref("log2", 0, 0, 10*4096)

	em.AddWrite(2, 2, refA)
	em.AddWrite(0, 10, refB)

	assert.Equal(t, 1, em.Len())

	extents := em.Lookup(0, 10)
	require.Len(t, extents, 1)
	assert.Equal(t, refB, extents[0].Ref)
}

func TestExtentMapTrimRemovesBlocks(t *testing.T) {
	var em ExtentMap

	refA := ref("log1", 0, 0, 5*4096)
	em.AddWrite(0, 5, refA)

	em.RemoveTrim(0, 5)

	assert.Equal(t, 0, em.Len())
	assert.Empty(t, em.Lookup(0, 5))
}

func TestExtentMapTrimSplitsExtent(t *testing.T) {
	// Original: blocks 0-4 (ref A)
	// Trim: block 2
	// Result: blocks 0-1 (ref A), blocks 3-4 (ref A)
	var em ExtentMap

	refA := ref("log1", 0, 0, 5*4096)
	em.AddWrite(0, 5, refA)

	em.RemoveTrim(2, 1)

	assert.Equal(t, 2, em.Len())

	extents := em.Lookup(0, 5)
	require.Len(t, extents, 2)

	assert.Equal(t, uint64(0), extents[0].StartBlock)
	assert.Equal(t, uint64(2), extents[0].NumBlocks)
	assert.Equal(t, refA, extents[0].Ref)

	assert.Equal(t, uint64(3), extents[1].StartBlock)
	assert.Equal(t, uint64(2), extents[1].NumBlocks)
	assert.Equal(t, refA, extents[1].Ref)
}

func TestExtentMapTrimPartialStart(t *testing.T) {
	var em ExtentMap

	refA := ref("log1", 0, 0, 5*4096)
	em.AddWrite(0, 5, refA)

	em.RemoveTrim(0, 2)

	assert.Equal(t, 1, em.Len())
	extents := em.Lookup(0, 5)
	require.Len(t, extents, 1)
	assert.Equal(t, uint64(2), extents[0].StartBlock)
	assert.Equal(t, uint64(3), extents[0].NumBlocks)
}

func TestExtentMapTrimPartialEnd(t *testing.T) {
	var em ExtentMap

	refA := ref("log1", 0, 0, 5*4096)
	em.AddWrite(0, 5, refA)

	em.RemoveTrim(3, 2)

	assert.Equal(t, 1, em.Len())
	extents := em.Lookup(0, 5)
	require.Len(t, extents, 1)
	assert.Equal(t, uint64(0), extents[0].StartBlock)
	assert.Equal(t, uint64(3), extents[0].NumBlocks)
}

func TestExtentMapLookupClipsToRange(t *testing.T) {
	var em ExtentMap

	refA := ref("log1", 0, 0, 10*4096)
	em.AddWrite(0, 10, refA)

	// Query only blocks 3-6
	extents := em.Lookup(3, 4)
	require.Len(t, extents, 1)
	assert.Equal(t, uint64(3), extents[0].StartBlock)
	assert.Equal(t, uint64(4), extents[0].NumBlocks)
	assert.Equal(t, refA, extents[0].Ref)
}

func TestExtentMapLookupReturnsMultiple(t *testing.T) {
	var em ExtentMap

	r1 := ref("log1", 0, 0, 4096)
	r2 := ref("log1", 1, 2, 4096)
	r3 := ref("log1", 2, 4, 4096)

	em.AddWrite(0, 1, r1)
	em.AddWrite(2, 1, r2)
	em.AddWrite(4, 1, r3)

	// Query range covering all
	extents := em.Lookup(0, 8)
	require.Len(t, extents, 3)
}

func TestExtentMapLookupEmpty(t *testing.T) {
	var em ExtentMap
	assert.Empty(t, em.Lookup(0, 10))
}

func TestExtentMapLookupNoOverlap(t *testing.T) {
	var em ExtentMap

	r1 := ref("log1", 0, 0, 4096)
	em.AddWrite(0, 1, r1)

	assert.Empty(t, em.Lookup(10, 5))
}

func TestExtentMapRefPreservedOnSplit(t *testing.T) {
	// Verify that split remnants keep the original ref (Block, Length unchanged)
	// so data offset can be computed at read time.
	var em ExtentMap

	refA := ref("log1", 0, 0, 5*4096)
	refB := ref("log2", 0, 0, 4096)

	em.AddWrite(0, 5, refA)
	em.AddWrite(0, 1, refB)

	extents := em.Lookup(0, 5)
	require.Len(t, extents, 2)

	// The remnant (blocks 1-4) should keep original ref with Block=0
	remnant := extents[1]
	assert.Equal(t, uint64(1), remnant.StartBlock)
	assert.Equal(t, uint64(0), remnant.Ref.Block)    // original entry block
	assert.Equal(t, uint32(5*4096), remnant.Ref.Length) // original entry length
}

func TestExtentMapConcurrentAccess(t *testing.T) {
	var em ExtentMap

	var wg sync.WaitGroup

	// Writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			block := uint64(i * 10)
			r := ref("log1", i, block, 10*4096)
			em.AddWrite(block, 10, r)
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			em.Lookup(0, 100)
		}()
	}

	wg.Wait()

	// After all writes, we should have coverage across blocks 0-99
	extents := em.Lookup(0, 100)
	assert.NotEmpty(t, extents)
}

func TestExtentMapOverlappingMultipleExtents(t *testing.T) {
	// Multiple disjoint extents, new write spans across them
	var em ExtentMap

	r1 := ref("log1", 0, 0, 2*4096)
	r2 := ref("log1", 1, 4, 2*4096)
	r3 := ref("log1", 2, 8, 2*4096)

	em.AddWrite(0, 2, r1)
	em.AddWrite(4, 2, r2)
	em.AddWrite(8, 2, r3)

	// New write spanning blocks 1-8 (overlaps all three)
	rNew := ref("log2", 0, 1, 8*4096)
	em.AddWrite(1, 8, rNew)

	extents := em.Lookup(0, 10)
	require.Len(t, extents, 3)

	// Block 0 from r1
	assert.Equal(t, uint64(0), extents[0].StartBlock)
	assert.Equal(t, uint64(1), extents[0].NumBlocks)
	assert.Equal(t, r1, extents[0].Ref)

	// Blocks 1-8 from rNew
	assert.Equal(t, uint64(1), extents[1].StartBlock)
	assert.Equal(t, uint64(8), extents[1].NumBlocks)
	assert.Equal(t, rNew, extents[1].Ref)

	// Block 9 from r3
	assert.Equal(t, uint64(9), extents[2].StartBlock)
	assert.Equal(t, uint64(1), extents[2].NumBlocks)
	assert.Equal(t, r3, extents[2].Ref)
}

func TestExtentMapTrimAcrossMultiple(t *testing.T) {
	var em ExtentMap

	r1 := ref("log1", 0, 0, 4096)
	r2 := ref("log1", 1, 2, 4096)

	em.AddWrite(0, 1, r1)
	em.AddWrite(2, 1, r2)

	// Trim blocks 0-2 (covers both extents)
	em.RemoveTrim(0, 3)

	assert.Equal(t, 0, em.Len())
}

func TestExtentMapInsertionOrder(t *testing.T) {
	// Add extents in reverse order — should still be sorted
	var em ExtentMap

	r3 := ref("log1", 2, 20, 4096)
	r2 := ref("log1", 1, 10, 4096)
	r1 := ref("log1", 0, 0, 4096)

	em.AddWrite(20, 1, r3)
	em.AddWrite(10, 1, r2)
	em.AddWrite(0, 1, r1)

	extents := em.Lookup(0, 30)
	require.Len(t, extents, 3)

	assert.Equal(t, uint64(0), extents[0].StartBlock)
	assert.Equal(t, uint64(10), extents[1].StartBlock)
	assert.Equal(t, uint64(20), extents[2].StartBlock)
}
