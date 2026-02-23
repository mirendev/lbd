package lbd

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"github.com/zeebo/xxh3"
	"golang.org/x/crypto/blake2b"
	_ "modernc.org/sqlite"
)

// benchDir creates a temporary directory on the real filesystem (not tmpfs)
// and returns it along with a cleanup function. The directory is created
// under the current working directory to ensure it lands on a real disk.
func benchDir(b *testing.B) (string, func()) {
	b.Helper()
	dir, err := os.MkdirTemp(".", ".bench-*")
	if err != nil {
		b.Fatal(err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		os.RemoveAll(dir)
		b.Fatal(err)
	}
	return abs, func() { os.RemoveAll(abs) }
}

// makeDeviceFile creates a file filled with random data at the given path.
func makeDeviceFile(b *testing.B, path string, size int64) {
	b.Helper()
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	buf := make([]byte, 1024*1024)
	remaining := size
	for remaining > 0 {
		n := int64(len(buf))
		if n > remaining {
			n = remaining
		}
		rand.Read(buf[:n])
		if _, err := f.Write(buf[:n]); err != nil {
			b.Fatal(err)
		}
		remaining -= n
	}
	if err := f.Sync(); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkSHA256Run measures SHA256 throughput on a single 60K run.
func BenchmarkSHA256Run(b *testing.B) {
	buf := make([]byte, ScanRunSize)
	rand.Read(buf)

	b.SetBytes(ScanRunSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := sha256.Sum256(buf)
		_ = h
	}
}

// BenchmarkCRC32Run measures CRC32 throughput on a single 60K run.
func BenchmarkCRC32Run(b *testing.B) {
	buf := make([]byte, ScanRunSize)
	rand.Read(buf)

	b.SetBytes(ScanRunSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = crc32.ChecksumIEEE(buf)
	}
}

// BenchmarkHashAndHex measures SHA256 + hex encoding (what the scanner does per run).
func BenchmarkHashAndHex(b *testing.B) {
	buf := make([]byte, ScanRunSize)
	rand.Read(buf)

	b.SetBytes(ScanRunSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := sha256.Sum256(buf)
		_ = hex.EncodeToString(h[:])
	}
}

// BenchmarkScanDevice benchmarks a full scan of a file with all data changed.
// This exercises the complete path: read, hash, DB lookup, log write.
func BenchmarkScanDevice(b *testing.B) {
	benchScan(b, 64*1024*1024, false)
}

// BenchmarkScanDeviceNoChanges benchmarks scanning when nothing has changed
// (second scan of same data). This is the steady-state hot path.
func BenchmarkScanDeviceNoChanges(b *testing.B) {
	benchScan(b, 64*1024*1024, true)
}

// BenchmarkHashRun benchmarks different hash algorithms on a single 60K run.
func BenchmarkHashRun(b *testing.B) {
	buf := make([]byte, ScanRunSize)
	rand.Read(buf)

	b.Run("SHA256", func(b *testing.B) {
		b.SetBytes(ScanRunSize)
		for i := 0; i < b.N; i++ {
			h := sha256.Sum256(buf)
			_ = h
		}
	})

	b.Run("MD5", func(b *testing.B) {
		b.SetBytes(ScanRunSize)
		for i := 0; i < b.N; i++ {
			h := md5.Sum(buf)
			_ = h
		}
	})

	b.Run("BLAKE2b-256", func(b *testing.B) {
		b.SetBytes(ScanRunSize)
		for i := 0; i < b.N; i++ {
			h := blake2b.Sum256(buf)
			_ = h
		}
	})

	b.Run("XXH3-128", func(b *testing.B) {
		b.SetBytes(ScanRunSize)
		for i := 0; i < b.N; i++ {
			h := xxh3.Hash128(buf)
			_ = h
		}
	})

	b.Run("CRC32", func(b *testing.B) {
		b.SetBytes(ScanRunSize)
		for i := 0; i < b.N; i++ {
			_ = crc32.ChecksumIEEE(buf)
		}
	})
}

// makeReadHashBench creates a benchmark that reads a 64MB file and hashes every run
// using the given hash function, returning a fixed-size hex string per run.
func makeReadHashBench(b *testing.B, name string, hashFn func([]byte) string) {
	b.Helper()

	size := int64(64 * 1024 * 1024)
	dir, cleanup := benchDir(b)
	defer cleanup()
	devicePath := filepath.Join(dir, "device")
	makeDeviceFile(b, devicePath, size)

	buf := make([]byte, ScanRunSize)
	totalRuns := size / ScanRunSize
	if size%ScanRunSize != 0 {
		totalRuns++
	}

	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dev, err := os.Open(devicePath)
		if err != nil {
			b.Fatal(err)
		}

		for r := int64(0); r < totalRuns; r++ {
			offset := r * ScanRunSize
			runLen := int64(ScanRunSize)
			if offset+runLen > size {
				runLen = size - offset
			}
			n, err := dev.ReadAt(buf[:runLen], offset)
			if err != nil && err != io.EOF {
				b.Fatal(err)
			}
			_ = hashFn(buf[:n])
		}

		dev.Close()
	}
}

// BenchmarkScanReadHashAlgos compares full read+hash throughput across algorithms.
func BenchmarkScanReadHashAlgos(b *testing.B) {
	b.Run("SHA256", func(b *testing.B) {
		makeReadHashBench(b, "SHA256", func(data []byte) string {
			h := sha256.Sum256(data)
			return hex.EncodeToString(h[:])
		})
	})

	b.Run("MD5", func(b *testing.B) {
		makeReadHashBench(b, "MD5", func(data []byte) string {
			h := md5.Sum(data)
			return hex.EncodeToString(h[:])
		})
	})

	b.Run("BLAKE2b-256", func(b *testing.B) {
		makeReadHashBench(b, "BLAKE2b-256", func(data []byte) string {
			h := blake2b.Sum256(data)
			return hex.EncodeToString(h[:])
		})
	})

	b.Run("XXH3-128", func(b *testing.B) {
		makeReadHashBench(b, "XXH3-128", func(data []byte) string {
			h := xxh3.Hash128(data)
			var buf [16]byte
			binary.LittleEndian.PutUint64(buf[:8], h.Lo)
			binary.LittleEndian.PutUint64(buf[8:], h.Hi)
			return hex.EncodeToString(buf[:])
		})
	})

	b.Run("CRC32", func(b *testing.B) {
		makeReadHashBench(b, "CRC32", func(data []byte) string {
			v := crc32.ChecksumIEEE(data)
			var buf [4]byte
			binary.LittleEndian.PutUint32(buf[:], v)
			return hex.EncodeToString(buf[:])
		})
	})
}

// BenchmarkScanTwoLevel benchmarks the XXH3-first, SHA256-on-match strategy.
func BenchmarkScanTwoLevel(b *testing.B) {
	size := int64(64 * 1024 * 1024)
	dir, cleanup := benchDir(b)
	defer cleanup()
	devicePath := filepath.Join(dir, "device")
	makeDeviceFile(b, devicePath, size)

	totalRuns := int(size / ScanRunSize)
	if size%ScanRunSize != 0 {
		totalRuns++
	}

	buf := make([]byte, ScanRunSize)

	// Pre-compute stored hashes (simulates the DB contents from a prior scan).
	type storedHash struct {
		xxh xxh3.Uint128
		sha [32]byte
	}
	stored := make([]storedHash, totalRuns)
	{
		dev, _ := os.Open(devicePath)
		for r := 0; r < totalRuns; r++ {
			offset := int64(r) * ScanRunSize
			runLen := int64(ScanRunSize)
			if offset+runLen > size {
				runLen = size - offset
			}
			dev.ReadAt(buf[:runLen], offset)
			stored[r].xxh = xxh3.Hash128(buf[:runLen])
			stored[r].sha = sha256.Sum256(buf[:runLen])
		}
		dev.Close()
	}

	// No changes: XXH3 matches every run → must also SHA256 every run.
	b.Run("NoChanges", func(b *testing.B) {
		b.SetBytes(size)
		for i := 0; i < b.N; i++ {
			dev, _ := os.Open(devicePath)
			for r := 0; r < totalRuns; r++ {
				offset := int64(r) * ScanRunSize
				runLen := int64(ScanRunSize)
				if offset+runLen > size {
					runLen = size - offset
				}
				n, _ := dev.ReadAt(buf[:runLen], offset)
				data := buf[:n]

				xh := xxh3.Hash128(data)
				if xh == stored[r].xxh {
					// XXH3 matched — confirm with SHA256
					sh := sha256.Sum256(data)
					_ = sh == stored[r].sha
				}
			}
			dev.Close()
		}
	})

	// All changed: XXH3 differs every run → SHA256 never computed.
	// We simulate this by zeroing the stored XXH3 values.
	b.Run("AllChanged", func(b *testing.B) {
		fakeStored := make([]storedHash, totalRuns)
		// Leave zero values so nothing matches.

		b.SetBytes(size)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dev, _ := os.Open(devicePath)
			for r := 0; r < totalRuns; r++ {
				offset := int64(r) * ScanRunSize
				runLen := int64(ScanRunSize)
				if offset+runLen > size {
					runLen = size - offset
				}
				n, _ := dev.ReadAt(buf[:runLen], offset)
				data := buf[:n]

				xh := xxh3.Hash128(data)
				if xh == fakeStored[r].xxh {
					sh := sha256.Sum256(data)
					_ = sh == fakeStored[r].sha
				}
			}
			dev.Close()
		}
	})
}

// alignedAlloc returns a byte slice of the given size whose starting address
// is aligned to align bytes. This is required for O_DIRECT reads.
func alignedAlloc(size, align int) []byte {
	raw := make([]byte, size+align)
	offset := align - int(uintptr(unsafe.Pointer(&raw[0]))%uintptr(align))
	if offset == align {
		offset = 0
	}
	return raw[offset : offset+size]
}

// BenchmarkScanMmapVsRead compares mmap vs ReadAt vs O_DIRECT for the read+hash loop.
func BenchmarkScanMmapVsRead(b *testing.B) {
	for _, sizeMB := range []int64{64, 512, 2048} {
		label := fmt.Sprintf("%dMB", sizeMB)
		size := sizeMB * 1024 * 1024
		b.Run(label, func(b *testing.B) {
			benchMmapVsRead(b, size)
		})
	}
}

func benchMmapVsRead(b *testing.B, size int64) {
	dir, cleanup := benchDir(b)
	defer cleanup()
	devicePath := filepath.Join(dir, "device")
	makeDeviceFile(b, devicePath, size)

	totalRuns := int(size / ScanRunSize)
	if size%ScanRunSize != 0 {
		totalRuns++
	}

	b.Run("ReadAt", func(b *testing.B) {
		buf := make([]byte, ScanRunSize)
		b.SetBytes(size)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dev, _ := os.Open(devicePath)
			for r := 0; r < totalRuns; r++ {
				offset := int64(r) * ScanRunSize
				runLen := int64(ScanRunSize)
				if offset+runLen > size {
					runLen = size - offset
				}
				n, err := dev.ReadAt(buf[:runLen], offset)
				if err != nil && err != io.EOF {
					b.Fatal(err)
				}
				h := sha256.Sum256(buf[:n])
				_ = hex.EncodeToString(h[:])
			}
			dev.Close()
		}
	})

	b.Run("Mmap", func(b *testing.B) {
		b.SetBytes(size)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dev, _ := os.Open(devicePath)
			fd := int(dev.Fd())
			data, err := syscall.Mmap(fd, 0, int(size), syscall.PROT_READ, syscall.MAP_PRIVATE)
			if err != nil {
				b.Fatal(err)
			}

			for r := 0; r < totalRuns; r++ {
				offset := r * ScanRunSize
				end := offset + ScanRunSize
				if int64(end) > size {
					end = int(size)
				}
				h := sha256.Sum256(data[offset:end])
				_ = hex.EncodeToString(h[:])
			}

			syscall.Munmap(data)
			dev.Close()
		}
	})

	b.Run("MmapAdvise", func(b *testing.B) {
		b.SetBytes(size)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			dev, _ := os.Open(devicePath)
			fd := int(dev.Fd())
			data, err := syscall.Mmap(fd, 0, int(size), syscall.PROT_READ, syscall.MAP_PRIVATE)
			if err != nil {
				b.Fatal(err)
			}
			// Hint sequential access
			madvise(data, syscall.MADV_SEQUENTIAL)

			for r := 0; r < totalRuns; r++ {
				offset := r * ScanRunSize
				end := offset + ScanRunSize
				if int64(end) > size {
					end = int(size)
				}
				h := sha256.Sum256(data[offset:end])
				_ = hex.EncodeToString(h[:])
			}

			syscall.Munmap(data)
			dev.Close()
		}
	})

	b.Run("DirectIO", func(b *testing.B) {
		buf := alignedAlloc(ScanRunSize, 4096)
		b.SetBytes(size)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			fd, err := syscall.Open(devicePath, syscall.O_RDONLY|syscall.O_DIRECT, 0)
			if err != nil {
				b.Fatal(err)
			}

			for r := 0; r < totalRuns; r++ {
				offset := int64(r) * ScanRunSize
				runLen := int64(ScanRunSize)
				if offset+runLen > size {
					runLen = size - offset
					// O_DIRECT requires reads aligned to filesystem block size.
					// Round up to 4096.
					aligned := (runLen + 4095) &^ 4095
					n, err := syscall.Pread(fd, buf[:aligned], offset)
					if err != nil {
						b.Fatal(err)
					}
					if int64(n) < runLen {
						runLen = int64(n)
					}
					h := sha256.Sum256(buf[:runLen])
					_ = hex.EncodeToString(h[:])
				} else {
					n, err := syscall.Pread(fd, buf[:runLen], offset)
					if err != nil {
						b.Fatal(err)
					}
					h := sha256.Sum256(buf[:n])
					_ = hex.EncodeToString(h[:])
				}
			}

			syscall.Close(fd)
		}
	})
}

// madvise calls the madvise syscall. syscall.Madvise doesn't exist on all
// platforms so we call it directly.
func madvise(b []byte, advice int) {
	_, _, _ = syscall.Syscall(syscall.SYS_MADVISE, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(advice))
}

// BenchmarkScanReadHash benchmarks just the read+hash loop with no SQLite.
// This isolates the I/O + SHA256 cost to show SQLite overhead by comparison.
func BenchmarkScanReadHash(b *testing.B) {
	size := int64(64 * 1024 * 1024)

	dir, cleanup := benchDir(b)
	defer cleanup()
	devicePath := filepath.Join(dir, "device")
	makeDeviceFile(b, devicePath, size)

	buf := make([]byte, ScanRunSize)
	totalRuns := size / ScanRunSize
	if size%ScanRunSize != 0 {
		totalRuns++
	}

	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dev, err := os.Open(devicePath)
		if err != nil {
			b.Fatal(err)
		}

		for r := int64(0); r < totalRuns; r++ {
			offset := r * ScanRunSize
			runLen := int64(ScanRunSize)
			if offset+runLen > size {
				runLen = size - offset
			}
			n, err := dev.ReadAt(buf[:runLen], offset)
			if err != nil && err != io.EOF {
				b.Fatal(err)
			}
			h := sha256.Sum256(buf[:n])
			_ = hex.EncodeToString(h[:])
		}

		dev.Close()
	}
}

func benchScan(b *testing.B, size int64, preseed bool) {
	b.Helper()

	dir, cleanup := benchDir(b)
	defer cleanup()
	devicePath := filepath.Join(dir, "device")
	dbPath := filepath.Join(dir, "hashes.db")
	logDir := filepath.Join(dir, "logs")
	os.MkdirAll(logDir, 0755)

	makeDeviceFile(b, devicePath, size)

	cfg := ScanConfig{
		DBPath:     dbPath,
		LogDir:     logDir,
		DevicePath: devicePath,
	}

	if preseed {
		// Run once to populate the DB so subsequent scans find no changes.
		if _, err := ScanDevice(cfg); err != nil {
			b.Fatal(err)
		}
		// Clean up log files from the seed run.
		entries, _ := os.ReadDir(logDir)
		for _, e := range entries {
			os.Remove(filepath.Join(logDir, e.Name()))
		}
	}

	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := ScanDevice(cfg)
		if err != nil {
			b.Fatal(err)
		}
		_ = result

		// Clean up log files between iterations to avoid filling disk.
		entries, _ := os.ReadDir(logDir)
		for _, e := range entries {
			os.Remove(filepath.Join(logDir, e.Name()))
		}
	}
}
