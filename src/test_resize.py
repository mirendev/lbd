#!/usr/bin/env python3
"""Real-module resize regressions. Run as root with the freshly built lbd loaded.

Requires lbdctl, bin/lbdlog, Python 3, e2fsprogs and mount. Creates only disposable
images/devices; never unloads the module or removes pre-existing devices. Exit 77
means the host cannot run this test. No mocks stand in for module execution.
"""
import errno
import fcntl
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parent.parent
CTL = ROOT / "src/lbdctl"
LOG = ROOT / "bin/lbdlog"
RESIZE = 0x40104C03  # _IOW('L', 3, 16)
MIB = 1024 * 1024


def run(*args):
    return subprocess.check_output([str(a) for a in args], text=True, timeout=60)


def main():
    if os.geteuid() or not Path("/dev/lbd-control").exists():
        print("SKIP: root and a loaded lbd module with /dev/lbd-control required")
        return 77
    for tool in (CTL, LOG, "mkfs.ext4", "resize2fs", "mount", "umount"):
        if not shutil.which(str(tool)):
            print(f"SKIP: missing {tool}")
            return 77

    devices, nodes = [], []
    mounted = False
    log_mount = None
    tmp = Path(tempfile.mkdtemp(prefix="lbd-resize-"))
    try:
        mount = tmp / "mnt"
        mount.mkdir()
        control = os.open("/dev/lbd-control", os.O_RDWR)

        def attach(image, logs):
            logs.mkdir(exist_ok=True)
            index = json.loads(run(CTL, "add", "--json", "--log-dir", logs,
                                   "--log-max-age", "1", "--log-max-size", "16384", image))["index"]
            devices.append(index)
            node = Path(f"/dev/lbd{index}")
            if not node.exists():
                major, minor = map(int, Path(f"/sys/block/lbd{index}/dev").read_text().split(":"))
                os.mknod(node, stat.S_IFBLK | 0o600, os.makedev(major, minor))
                nodes.append(node)
            return index, node

        def resize(index, image, size, error=None):
            fd = os.open(image, os.O_RDONLY)
            try:
                try:
                    fcntl.ioctl(control, RESIZE, struct.pack("=iiQ", index, fd, size))
                except OSError as exc:
                    if exc.errno != error:
                        raise
                else:
                    assert error is None, f"expected errno {error}"
            finally:
                os.close(fd)

        def capacity(node):
            with open(node, "rb", buffering=0) as f:
                return struct.unpack("=Q", fcntl.ioctl(f, 0x80081272, bytes(8)))[0]

        try:
            image, other, logs = tmp / "disk.raw", tmp / "other.raw", tmp / "logs"
            for path in (image, other):
                with open(path, "wb") as f:
                    f.truncate(64 * MIB)
            index, node = attach(image, logs)
            resize(index, other, 128 * MIB, errno.ESTALE)
            resize(index, image, 32 * MIB, errno.EINVAL)
            resize(index, image, 0, errno.EINVAL)
            resize(index, image, 64 * MIB + 1, errno.EINVAL)
            assert capacity(node) == image.stat().st_size == 64 * MIB

            # Open descriptor remains usable across growth, including new tail.
            fd = os.open(node, os.O_RDWR)
            try:
                os.pwrite(fd, b"A" * 4096, 0)
                run(CTL, "resize", "--json", "--size", 128 * MIB, "--backing", image, index)
                assert capacity(node) == image.stat().st_size == 128 * MIB
                # No writes after growth: completed headers alone restore size.
                out = tmp / "no-writes.raw"
                run(LOG, "replay", logs, out)
                assert out.stat().st_size == 128 * MIB
                assert os.pread(fd, 4096, 0) == b"A" * 4096
                assert os.pread(fd, 4096, 100 * MIB) == bytes(4096)
                os.pwrite(fd, b"Z" * 4096, 100 * MIB)
                os.fsync(fd)
                resize(index, image, 128 * MIB)
                run(LOG, "replay", logs, out)
                with open(out, "rb") as f:
                    f.seek(100 * MIB)
                    assert f.read(4096) == b"Z" * 4096
            finally:
                os.close(fd)

            # Simulate process interruption after image growth, before ioctl.
            with open(image, "r+b") as f:
                f.truncate(160 * MIB)
                os.fsync(f.fileno())
            assert capacity(node) == 128 * MIB
            resize(index, image, 160 * MIB)
            resize(index, image, 160 * MIB)
            assert capacity(node) == 160 * MIB

            # Online ext4 plus ongoing buffered I/O and age/size rotations.
            run("mkfs.ext4", "-q", "-F", node)
            run("mount", node, mount)
            mounted = True
            failures = []
            stop = threading.Event()
            ready = threading.Event()

            def writer():
                try:
                    with open(mount / "active", "w+b", buffering=0) as f:
                        for i in range(10000):
                            if stop.is_set():
                                break
                            data = struct.pack("=Q", i) * 512
                            f.seek(0)
                            f.write(data)
                            os.fsync(f.fileno())
                            f.seek(0)
                            assert f.read(4096) == data
                            ready.set()
                except BaseException as exc:
                    failures.append(exc)

            thread = threading.Thread(target=writer)
            thread.start()
            try:
                assert ready.wait(10), "writer did not start"
                resize(index, image, 224 * MIB)
                run("resize2fs", node)
                assert capacity(node) == 224 * MIB
                assert os.statvfs(mount).f_blocks * os.statvfs(mount).f_frsize > 160 * MIB
                # Mounted users prevent detach, not growth.
                result = subprocess.run([str(CTL), "remove", str(index)], capture_output=True)
                assert result.returncode != 0
            finally:
                stop.set()
                thread.join(timeout=30)
                assert not thread.is_alive(), "writer stuck during resize"
            assert not failures, failures
            run("umount", mount)
            mounted = False

            # Log-open failure after durable image extension: capacity stays old,
            # retry completes metadata/device growth without shrinking image.
            run(CTL, "remove", index)
            devices.remove(index)
            failure_logs = tmp / "failure-logs"
            failure_logs.mkdir()
            # Permissions cannot inject failure for root; a read-only bind mount can.
            run("mount", "--bind", failure_logs, failure_logs)
            log_mount = failure_logs
            run("mount", "-o", "remount,bind,ro", failure_logs)
            # Attach after mounting: the device pins this mount's path.
            index, node = attach(image, failure_logs)
            resize(index, image, 256 * MIB, errno.EROFS)
            assert capacity(node) == 224 * MIB
            assert image.stat().st_size == 256 * MIB
            run("mount", "-o", "remount,bind,rw", failure_logs)
            resize(index, image, 256 * MIB)
            assert capacity(node) == 256 * MIB

            # Detach releases log_dir_path before unmounting its bind mount.
            run(CTL, "remove", index)
            devices.remove(index)
            run("umount", failure_logs)
            log_mount = None

            # A stale index now names another inode. No CLI path string trust.
            recycled, _ = attach(other, tmp / "other-logs")
            assert recycled == index, "run on an isolated module for index reuse coverage"
            resize(recycled, image, 320 * MIB, errno.ESTALE)
            assert other.stat().st_size == 64 * MIB

            qcow = tmp / "disk.qcow2"
            run(CTL, "create", "--size", "64M", qcow)
            qi, _ = attach(qcow, tmp / "qcow-logs")
            resize(qi, qcow, 128 * MIB, errno.EOPNOTSUPP)
            # A log flush that fails with a nearly full buffer must not leave a
            # torn record: once the log recovers, every segment must still parse.
            torn_logs = tmp / "torn-logs"
            torn_logs.mkdir()
            run("mount", "--bind", torn_logs, torn_logs)
            log_mount = torn_logs
            torn = tmp / "torn.img"
            with open(torn, "wb") as f:
                f.truncate(64 * MIB)
            run("mount", "-o", "remount,bind,ro", torn_logs)
            ti, tnode = attach(torn, torn_logs)
            fd = os.open(tnode, os.O_WRONLY)
            try:
                # Random data defeats LZ4, so records overflow the 5 MiB buffer
                # while every flush fails.
                for i in range(12):
                    os.pwrite(fd, os.urandom(MIB), i * MIB)
                    try:
                        os.fsync(fd)
                    except OSError:
                        pass
                run("mount", "-o", "remount,bind,rw", torn_logs)
                os.pwrite(fd, os.urandom(MIB), 20 * MIB)
                os.fsync(fd)
            finally:
                os.close(fd)
            run(CTL, "remove", ti)
            devices.remove(ti)
            run("umount", torn_logs)
            log_mount = None
            segments = sorted(torn_logs.glob("*.log"))
            assert segments, "no segment written after the log recovered"
            run(LOG, "show", *segments)

            print("PASS: identity, shrink/alignment, live fd, no-write recovery, tail replay,")
            print("      interrupted growth, mounted ext4 I/O, log failure retry, recycled index, qcow rejection,")
            print("      no torn records after failed flushes")
        finally:
            if mounted:
                run("umount", mount)
                mounted = False
            if log_mount is not None:
                run("mount", "-o", "remount,bind,rw", log_mount)
            for index in reversed(devices):
                run(CTL, "remove", index)
            if log_mount is not None:
                run("umount", log_mount)
                log_mount = None
            for node in nodes:
                node.unlink(missing_ok=True)
            os.close(control)
    finally:
        # Never recursively delete through a live mount if teardown itself fails.
        if not mounted and log_mount is None:
            shutil.rmtree(tmp)
        else:
            print(f"Preserving {tmp}: mount cleanup did not complete", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
