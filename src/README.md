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
