# LBD Kernel Module

LBD (Logging Block Device) is a block device driver backed by a file (like loop) that logs all write operations for change tracking, audit, and replay.

## Prerequisites

- Linux kernel headers for your running kernel
- GCC and make
- (Optional) DKMS for automatic rebuilds on kernel upgrades

Debian/Ubuntu:

```
sudo apt install build-essential linux-headers-$(uname -r) dkms
```

Fedora/RHEL:

```
sudo dnf install gcc make kernel-devel dkms
```

## Manual Build

From this directory:

```
make
sudo insmod lbd.ko
```

This produces `lbd.ko` (the kernel module) and `lbdctl` (the userspace control tool).

To build against a different kernel:

```
make KDIR=/lib/modules/6.8.0-100-generic/build
```

To unload:

```
sudo rmmod lbd
```

## Install with DKMS

DKMS automatically rebuilds the module whenever a new kernel is installed.

### From a local checkout

```
sudo cp -r . /usr/src/lbd-0.1.0
sudo dkms add lbd/0.1.0
sudo dkms build lbd/0.1.0
sudo dkms install lbd/0.1.0
```

### Load the module

```
sudo modprobe lbd
```

### Verify

```
dkms status | grep lbd
lsmod | grep lbd
```

### Uninstall

```
sudo dkms remove lbd/0.1.0 --all
sudo rm -rf /usr/src/lbd-0.1.0
```

## Install lbdctl

After building, copy the control tool somewhere in your PATH:

```
sudo install -m 755 lbdctl /usr/local/bin/
```

## Online raw disk growth

With the matching module loaded, grow an attached raw regular-file disk without
detaching it or closing mounted users:

```sh
lbdctl resize --json --size 2147483648 --backing /var/lib/disks/data.raw 0
```

The size is a positive, 4096-aligned decimal byte count, no larger than
9223372036854771712. Shrinking either the device or its backing file is rejected.
The CLI opens `--backing` and passes its descriptor to the kernel, which compares
the pinned inode with the attached backing inode. A stale device index or a
replaced path therefore cannot grow a different backing file. Hard links to the
same inode are valid. The kernel uses its existing writable backing file, not
the supplied descriptor, to extend the image. The descriptor is only an identity
check; this operation still requires access to `/dev/lbd-control`.

The ioctl ABI is `LBD_CTL_RESIZE = _IOW('L', 3, struct lbd_ctl_resize)`:

```c
struct lbd_ctl_resize {
    __s32 index;
    __s32 backing_fd;
    __u64 size;
}; /* 16 bytes on native and compat callers; no output fields */
```

Success returns zero; JSON output contains `device`, `index`, and `size`.
The ioctl returns `ESTALE` for a different backing inode, `ENODEV` for an absent
index, `EBUSY` for an unbound/removing device, `EBADF` for an invalid descriptor,
and `EINVAL` for an invalid size, shrink, or a backing file smaller than the
current device. Qcow2-lz4, thin snapshots, recognized standard qcow2 containers,
and kernels older than 5.10 return `EOPNOTSUPP`. An old loaded module returns
`ENOTTY`; installing a new CLI alone does not add resize support. Other image
containers must not be attached as raw files: raw detection is not a general
image-format validator.

Resize holds the device lifecycle mutex, freezes and drains the request queue,
then serializes with log rotation. It extends and fsyncs the attached image,
finishes the old segment, and publishes a new header-only segment containing the
target size. The segment and log directory are fsynced before live block-device
capacity is updated. Watch events report each segment's own header size. This
keeps growth recoverable even when no writes follow it. It does not strengthen
the existing best-effort logging contract for ordinary writes.

If any image or log operation fails, the ioctl reports the error without
publishing new device capacity; the image may already be larger. Retry the same
target. Pre-grown image/device-old and equal-size retries are supported, including
reattach after interrupted growth. Equal-size retries also publish a durable size
boundary. Do not roll back by truncating the image. Callers must exclude external
backing-file mutation and serialize the entire image/device/filesystem operation;
for example, hold an advisory `flock` on the backing inode throughout. Lbd does
not acquire that flock, so it can run while its caller holds it.

Filesystem growth is separate. After successful device growth, use the
filesystem's online grow operation, such as `resize2fs /dev/lbd0` for ext4.
Do not run partition rereads, detach, or remount as part of resize.

### Recovery and compaction

Updated `lbdlog replay`, repack, and GC preserve the maximum segment-header
capacity, including header-only segments and fully shadowed data segments.
Full raw and qcow2 replay use that maximum; incremental raw replay extends but
never shrinks existing output. Incremental qcow2 replay explicitly rejects a
larger capacity without advancing its checkpoint; replay all segments into a new
qcow2 image instead. There is no `QCow2Image` grow API. Consumers implementing
their own replay must honor `Header.DeviceSize`, even when a segment has no
entries, before advancing their restore checkpoint.

### Real-module regression test

On an isolated Linux host with module loading and mount privileges, build and
load this checkout's module, build the Go commands from the repository root,
then run:

```sh
go build -o bin/ ./cmd/...
sudo python3 src/test_resize.py
```

The test creates disposable files and devices and exercises identity checks,
shrink rejection, an already-open block descriptor, no-write size recovery,
tail-write replay, pre-grown image retries, mounted ext4 growth during I/O and
rotation, a read-only log mount failure and retry, recycled indexes, and qcow2
rejection. It never unloads the module or removes pre-existing devices. Exit 77
means prerequisites are unavailable, not a passing module test. Power-loss and
kernel-version matrix testing still require suitable hosts.
