package lbd

import (
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
)

// Command types written to /dev/lbd-control.

// WatchCommand subscribes to log rotation events.
type WatchCommand struct {
	Cmd      string `cbor:"1,keyasint"`
	DevIndex *int   `cbor:"2,keyasint,omitempty"`
}

// ManageMissesCommand registers as the miss handler for a device.
type ManageMissesCommand struct {
	Cmd      string `cbor:"1,keyasint"`
	DevIndex int    `cbor:"2,keyasint"`
}

// MissResponse sends a continue or retry response.
type MissResponse struct {
	Cmd string `cbor:"1,keyasint"`
}

// SwapCommand tells the kernel to swap the base qcow2 path.
type SwapCommand struct {
	Cmd  string `cbor:"1,keyasint"`
	Path string `cbor:"3,keyasint"`
}

// Event types read from /dev/lbd-control.

// LogRotatedEvent is emitted when a log segment is rotated.
type LogRotatedEvent struct {
	Type       string `cbor:"1,keyasint"`
	DevIndex   int    `cbor:"2,keyasint"`
	Label      string `cbor:"3,keyasint"`
	Dir        string `cbor:"4,keyasint"`
	Seq        uint64 `cbor:"5,keyasint"`
	DeviceSize uint64 `cbor:"6,keyasint"`
}

// BlockMissEvent is emitted when a cluster read misses.
type BlockMissEvent struct {
	Type         string `cbor:"1,keyasint"`
	DevIndex     int    `cbor:"2,keyasint"`
	ClusterIndex uint64 `cbor:"3,keyasint"`
}

// ControlConn wraps an open fd to /dev/lbd-control.
type ControlConn struct {
	f      *os.File
	encOpt cbor.EncMode
	decOpt cbor.DecMode
}

// OpenControl opens /dev/lbd-control for reading and writing.
func OpenControl() (*ControlConn, error) {
	f, err := os.OpenFile("/dev/lbd-control", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/lbd-control: %w", err)
	}
	return NewControlConn(f)
}

// NewControlConn creates a ControlConn from an already-open file.
func NewControlConn(f *os.File) (*ControlConn, error) {
	em, err := cbor.EncOptions{}.EncMode()
	if err != nil {
		return nil, fmt.Errorf("cbor enc mode: %w", err)
	}
	dm, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		return nil, fmt.Errorf("cbor dec mode: %w", err)
	}
	return &ControlConn{f: f, encOpt: em, decOpt: dm}, nil
}

// Close closes the underlying file.
func (c *ControlConn) Close() error {
	return c.f.Close()
}

// sendCommand marshals cmd to CBOR and writes it in a single Write syscall.
func (c *ControlConn) sendCommand(cmd interface{}) error {
	data, err := c.encOpt.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("cbor marshal: %w", err)
	}
	_, err = c.f.Write(data)
	return err
}

// SendWatch subscribes to log rotation events. If dev is non-nil, only
// events for that device index are delivered.
func (c *ControlConn) SendWatch(dev *int) error {
	return c.sendCommand(WatchCommand{Cmd: "watch", DevIndex: dev})
}

// SendManageMisses registers as the miss handler for the given device.
func (c *ControlConn) SendManageMisses(dev int) error {
	return c.sendCommand(ManageMissesCommand{Cmd: "manage_misses", DevIndex: dev})
}

// SendRetry tells the kernel to retry the missed I/O.
func (c *ControlConn) SendRetry() error {
	return c.sendCommand(MissResponse{Cmd: "retry"})
}

// SendContinue tells the kernel the miss was handled (zero-fill).
func (c *ControlConn) SendContinue() error {
	return c.sendCommand(MissResponse{Cmd: "continue"})
}

// SendSwap tells the kernel to swap the base qcow2 file path.
func (c *ControlConn) SendSwap(path string) error {
	return c.sendCommand(SwapCommand{Cmd: "swap", Path: path})
}

// ReadEvent reads one CBOR message from the control fd and returns
// either a *LogRotatedEvent or *BlockMissEvent.
func (c *ControlConn) ReadEvent() (interface{}, error) {
	buf := make([]byte, 4096)
	n, err := c.f.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	buf = buf[:n]

	// Peek at the type field to discriminate.
	var raw map[int]cbor.RawMessage
	if err := c.decOpt.Unmarshal(buf, &raw); err != nil {
		return nil, fmt.Errorf("cbor unmarshal raw: %w", err)
	}

	typeRaw, ok := raw[1]
	if !ok {
		return nil, fmt.Errorf("missing type field (key 1)")
	}

	var typeStr string
	if err := c.decOpt.Unmarshal(typeRaw, &typeStr); err != nil {
		return nil, fmt.Errorf("cbor unmarshal type: %w", err)
	}

	switch typeStr {
	case "log_rotated":
		var ev LogRotatedEvent
		if err := c.decOpt.Unmarshal(buf, &ev); err != nil {
			return nil, fmt.Errorf("cbor unmarshal log_rotated: %w", err)
		}
		return &ev, nil

	case "block_miss":
		var ev BlockMissEvent
		if err := c.decOpt.Unmarshal(buf, &ev); err != nil {
			return nil, fmt.Errorf("cbor unmarshal block_miss: %w", err)
		}
		return &ev, nil

	default:
		return nil, fmt.Errorf("unknown event type: %q", typeStr)
	}
}

// MarshalCommand marshals a command to CBOR bytes (for testing).
func (c *ControlConn) MarshalCommand(cmd interface{}) ([]byte, error) {
	return c.encOpt.Marshal(cmd)
}
