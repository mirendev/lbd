package lbd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- BlockSet unit tests ---

func TestBlockSetAddDisjoint(t *testing.T) {
	var bs BlockSet

	bs.Add(10, 20)
	bs.Add(30, 40)
	bs.Add(50, 60)

	require.Len(t, bs.Intervals, 3)
	assert.Equal(t, Interval{10, 20}, bs.Intervals[0])
	assert.Equal(t, Interval{30, 40}, bs.Intervals[1])
	assert.Equal(t, Interval{50, 60}, bs.Intervals[2])
}

func TestBlockSetAddOverlapping(t *testing.T) {
	var bs BlockSet

	bs.Add(10, 20)
	bs.Add(15, 30)

	require.Len(t, bs.Intervals, 1)
	assert.Equal(t, Interval{10, 30}, bs.Intervals[0])
}

func TestBlockSetAddAdjacent(t *testing.T) {
	var bs BlockSet

	bs.Add(10, 20)
	bs.Add(20, 30)

	require.Len(t, bs.Intervals, 1)
	assert.Equal(t, Interval{10, 30}, bs.Intervals[0])
}

func TestBlockSetAddMergesMultiple(t *testing.T) {
	var bs BlockSet

	bs.Add(0, 10)
	bs.Add(20, 30)
	bs.Add(40, 50)

	require.Len(t, bs.Intervals, 3)

	bs.Add(5, 45)

	require.Len(t, bs.Intervals, 1)
	assert.Equal(t, Interval{0, 50}, bs.Intervals[0])
}

func TestBlockSetAddInsertionOrder(t *testing.T) {
	var bs BlockSet

	bs.Add(50, 60)
	bs.Add(30, 40)
	bs.Add(10, 20)

	require.Len(t, bs.Intervals, 3)
	assert.Equal(t, Interval{10, 20}, bs.Intervals[0])
	assert.Equal(t, Interval{30, 40}, bs.Intervals[1])
	assert.Equal(t, Interval{50, 60}, bs.Intervals[2])
}

func TestBlockSetAddSuperset(t *testing.T) {
	var bs BlockSet

	bs.Add(10, 20)
	bs.Add(5, 25)

	require.Len(t, bs.Intervals, 1)
	assert.Equal(t, Interval{5, 25}, bs.Intervals[0])
}

func TestBlockSetAddSubset(t *testing.T) {
	var bs BlockSet

	bs.Add(5, 25)
	bs.Add(10, 20)

	require.Len(t, bs.Intervals, 1)
	assert.Equal(t, Interval{5, 25}, bs.Intervals[0])
}

func TestBlockSetCoversAllEmpty(t *testing.T) {
	var bs BlockSet
	assert.False(t, bs.CoversAll(0, 10))
}

func TestBlockSetCoversAllExactMatch(t *testing.T) {
	var bs BlockSet
	bs.Add(10, 20)
	assert.True(t, bs.CoversAll(10, 20))
}

func TestBlockSetCoversAllSubrange(t *testing.T) {
	var bs BlockSet
	bs.Add(0, 100)
	assert.True(t, bs.CoversAll(10, 20))
	assert.True(t, bs.CoversAll(0, 1))
	assert.True(t, bs.CoversAll(99, 100))
}

func TestBlockSetCoversAllPartiallyUncovered(t *testing.T) {
	var bs BlockSet
	bs.Add(10, 20)

	assert.False(t, bs.CoversAll(5, 15))
	assert.False(t, bs.CoversAll(15, 25))
	assert.False(t, bs.CoversAll(5, 25))
}

func TestBlockSetCoversAllGap(t *testing.T) {
	var bs BlockSet
	bs.Add(0, 10)
	bs.Add(20, 30)

	assert.False(t, bs.CoversAll(5, 25))
	assert.True(t, bs.CoversAll(0, 10))
	assert.True(t, bs.CoversAll(20, 30))
}

func TestBlockSetCoversAllDisjointRange(t *testing.T) {
	var bs BlockSet
	bs.Add(0, 10)

	assert.False(t, bs.CoversAll(50, 60))
}

// --- BlockSet.Uncovered unit tests ---

func TestBlockSetUncoveredEmpty(t *testing.T) {
	var bs BlockSet
	gaps := bs.Uncovered(0, 10)
	assert.Equal(t, []Interval{{0, 10}}, gaps)
}

func TestBlockSetUncoveredFullyCovered(t *testing.T) {
	var bs BlockSet
	bs.Add(0, 10)
	gaps := bs.Uncovered(0, 10)
	assert.Empty(t, gaps)
}

func TestBlockSetUncoveredSupersetCovered(t *testing.T) {
	var bs BlockSet
	bs.Add(0, 20)
	gaps := bs.Uncovered(5, 15)
	assert.Empty(t, gaps)
}

func TestBlockSetUncoveredGapInMiddle(t *testing.T) {
	var bs BlockSet
	bs.Add(0, 3)
	bs.Add(7, 10)
	gaps := bs.Uncovered(0, 10)
	assert.Equal(t, []Interval{{3, 7}}, gaps)
}

func TestBlockSetUncoveredLeadingGap(t *testing.T) {
	var bs BlockSet
	bs.Add(5, 10)
	gaps := bs.Uncovered(0, 10)
	assert.Equal(t, []Interval{{0, 5}}, gaps)
}

func TestBlockSetUncoveredTrailingGap(t *testing.T) {
	var bs BlockSet
	bs.Add(0, 5)
	gaps := bs.Uncovered(0, 10)
	assert.Equal(t, []Interval{{5, 10}}, gaps)
}

func TestBlockSetUncoveredMultipleGaps(t *testing.T) {
	var bs BlockSet
	bs.Add(2, 4)
	bs.Add(6, 8)
	gaps := bs.Uncovered(0, 10)
	assert.Equal(t, []Interval{{0, 2}, {4, 6}, {8, 10}}, gaps)
}

func TestBlockSetUncoveredPartialOverlap(t *testing.T) {
	var bs BlockSet
	bs.Add(5, 20)
	gaps := bs.Uncovered(0, 10)
	assert.Equal(t, []Interval{{0, 5}}, gaps)
}

func TestBlockSetUncoveredNoOverlap(t *testing.T) {
	var bs BlockSet
	bs.Add(20, 30)
	gaps := bs.Uncovered(0, 10)
	assert.Equal(t, []Interval{{0, 10}}, gaps)
}
