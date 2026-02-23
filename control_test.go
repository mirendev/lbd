package lbd

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatchCommandEncoding(t *testing.T) {
	em, err := cbor.EncOptions{}.EncMode()
	require.NoError(t, err)
	dm, err := cbor.DecOptions{}.DecMode()
	require.NoError(t, err)

	// Without device filter
	cmd := WatchCommand{Cmd: "watch"}
	data, err := em.Marshal(cmd)
	require.NoError(t, err)

	var raw map[int]interface{}
	require.NoError(t, dm.Unmarshal(data, &raw))
	assert.Equal(t, "watch", raw[1])
	_, hasKey2 := raw[2]
	assert.False(t, hasKey2, "key 2 should be omitted when DevIndex is nil")

	// With device filter
	dev := 3
	cmd2 := WatchCommand{Cmd: "watch", DevIndex: &dev}
	data2, err := em.Marshal(cmd2)
	require.NoError(t, err)

	var raw2 map[int]interface{}
	require.NoError(t, dm.Unmarshal(data2, &raw2))
	assert.Equal(t, "watch", raw2[1])
	assert.Equal(t, uint64(3), raw2[2])
}

func TestManageMissesCommandEncoding(t *testing.T) {
	em, err := cbor.EncOptions{}.EncMode()
	require.NoError(t, err)
	dm, err := cbor.DecOptions{}.DecMode()
	require.NoError(t, err)

	cmd := ManageMissesCommand{Cmd: "manage_misses", DevIndex: 5}
	data, err := em.Marshal(cmd)
	require.NoError(t, err)

	var raw map[int]interface{}
	require.NoError(t, dm.Unmarshal(data, &raw))
	assert.Equal(t, "manage_misses", raw[1])
	assert.Equal(t, uint64(5), raw[2])
}

func TestMissResponseEncoding(t *testing.T) {
	em, err := cbor.EncOptions{}.EncMode()
	require.NoError(t, err)
	dm, err := cbor.DecOptions{}.DecMode()
	require.NoError(t, err)

	for _, cmd := range []string{"retry", "continue"} {
		resp := MissResponse{Cmd: cmd}
		data, err := em.Marshal(resp)
		require.NoError(t, err)

		var raw map[int]interface{}
		require.NoError(t, dm.Unmarshal(data, &raw))
		assert.Equal(t, cmd, raw[1])
	}
}

func TestSwapCommandEncoding(t *testing.T) {
	em, err := cbor.EncOptions{}.EncMode()
	require.NoError(t, err)
	dm, err := cbor.DecOptions{}.DecMode()
	require.NoError(t, err)

	cmd := SwapCommand{Cmd: "swap", Path: "/mnt/base.qcow2"}
	data, err := em.Marshal(cmd)
	require.NoError(t, err)

	var raw map[int]interface{}
	require.NoError(t, dm.Unmarshal(data, &raw))
	assert.Equal(t, "swap", raw[1])
	assert.Equal(t, "/mnt/base.qcow2", raw[3])
	// Key 2 should not be present
	_, hasKey2 := raw[2]
	assert.False(t, hasKey2, "swap command should not have key 2")
}

func TestLogRotatedEventDecoding(t *testing.T) {
	em, err := cbor.EncOptions{}.EncMode()
	require.NoError(t, err)
	dm, err := cbor.DecOptions{}.DecMode()
	require.NoError(t, err)

	// Build a log_rotated event using integer keys (as kernel does)
	raw := map[int]interface{}{
		1: "log_rotated",
		2: uint64(0),
		3: "40000000deadbeef00000000",
		4: "/var/log/lbd",
		5: uint64(42),
		6: uint64(1073741824),
	}
	data, err := em.Marshal(raw)
	require.NoError(t, err)

	var ev LogRotatedEvent
	require.NoError(t, dm.Unmarshal(data, &ev))
	assert.Equal(t, "log_rotated", ev.Type)
	assert.Equal(t, 0, ev.DevIndex)
	assert.Equal(t, "40000000deadbeef00000000", ev.Label)
	assert.Equal(t, "/var/log/lbd", ev.Dir)
	assert.Equal(t, uint64(42), ev.Seq)
	assert.Equal(t, uint64(1073741824), ev.DeviceSize)
}

func TestBlockMissEventDecoding(t *testing.T) {
	em, err := cbor.EncOptions{}.EncMode()
	require.NoError(t, err)
	dm, err := cbor.DecOptions{}.DecMode()
	require.NoError(t, err)

	raw := map[int]interface{}{
		1: "block_miss",
		2: uint64(1),
		3: uint64(256),
	}
	data, err := em.Marshal(raw)
	require.NoError(t, err)

	var ev BlockMissEvent
	require.NoError(t, dm.Unmarshal(data, &ev))
	assert.Equal(t, "block_miss", ev.Type)
	assert.Equal(t, 1, ev.DevIndex)
	assert.Equal(t, uint64(256), ev.ClusterIndex)
}

func TestEventRoundTrip(t *testing.T) {
	em, err := cbor.EncOptions{}.EncMode()
	require.NoError(t, err)
	dm, err := cbor.DecOptions{}.DecMode()
	require.NoError(t, err)

	// Encode a LogRotatedEvent, then decode back
	orig := LogRotatedEvent{
		Type:       "log_rotated",
		DevIndex:   2,
		Label:      "test_label",
		Dir:        "/some/dir",
		Seq:        99,
		DeviceSize: 500 * 1024 * 1024,
	}

	data, err := em.Marshal(orig)
	require.NoError(t, err)

	var decoded LogRotatedEvent
	require.NoError(t, dm.Unmarshal(data, &decoded))
	assert.Equal(t, orig, decoded)
}

func TestCommandKeyLayout(t *testing.T) {
	// Verify that command keys match kernel expectations:
	// WatchCommand: key 1 = cmd, key 2 = dev_index
	// SwapCommand: key 1 = cmd, key 3 = path
	em, err := cbor.EncOptions{}.EncMode()
	require.NoError(t, err)
	dm, err := cbor.DecOptions{}.DecMode()
	require.NoError(t, err)

	dev := 0
	watchData, err := em.Marshal(WatchCommand{Cmd: "watch", DevIndex: &dev})
	require.NoError(t, err)

	var watchMap map[int]interface{}
	require.NoError(t, dm.Unmarshal(watchData, &watchMap))
	assert.Contains(t, watchMap, 1)
	assert.Contains(t, watchMap, 2)

	swapData, err := em.Marshal(SwapCommand{Cmd: "swap", Path: "/x"})
	require.NoError(t, err)

	var swapMap map[int]interface{}
	require.NoError(t, dm.Unmarshal(swapData, &swapMap))
	assert.Contains(t, swapMap, 1)
	assert.Contains(t, swapMap, 3)
	assert.NotContains(t, swapMap, 2)
}
