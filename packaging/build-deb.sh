#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$REPO_ROOT/src"

NAME="lbd-dkms"
VERSION="0.1.0"
ARCH="all"
PKG="${NAME}_${VERSION}_${ARCH}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Source files to package (kernel module only, no build artifacts)
SRC_FILES=(
    Makefile dkms.conf
    lbd_main.c lbd.h
    lbd_qcow2.c lbd_qcow2.h lbd_qcow2_format.h
    lbdctl.c
    cbor_enc.h cbor_dec.h
    lz4_kcompat.h
)

# Install source tree
DEST="$WORK/$PKG/usr/src/lbd-$VERSION"
mkdir -p "$DEST/lz4"

for f in "${SRC_FILES[@]}"; do
    cp "$SRC_DIR/$f" "$DEST/$f"
done
cp "$SRC_DIR/lz4/lz4.c" "$SRC_DIR/lz4/lz4.h" "$DEST/lz4/"

# DEBIAN control
mkdir -p "$WORK/$PKG/DEBIAN"

cat > "$WORK/$PKG/DEBIAN/control" <<EOF
Package: $NAME
Version: $VERSION
Architecture: $ARCH
Maintainer: Evan Phoenix <evan@miren.dev>
Depends: dkms (>= 2.1.0.0)
Section: kernel
Priority: optional
Homepage: https://miren.dev/lbd
Description: LBD (Logging Block Device) kernel module - DKMS source
 A block device driver backed by a file that logs all write operations
 for change tracking, audit, and replay. This package provides the
 source for building the module with DKMS.
EOF

cat > "$WORK/$PKG/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e

NAME="lbd"
VERSION="0.1.0"

case "$1" in
    configure)
        if [ -x "$(command -v dkms)" ]; then
            dkms add -m "$NAME" -v "$VERSION" --rpm_safe_upgrade 2>/dev/null || true
            dkms build -m "$NAME" -v "$VERSION" || true
            dkms install -m "$NAME" -v "$VERSION" --force || true
        fi
        ;;
esac

exit 0
POSTINST

cat > "$WORK/$PKG/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e

NAME="lbd"
VERSION="0.1.0"

case "$1" in
    remove|upgrade)
        if [ -x "$(command -v dkms)" ]; then
            dkms remove -m "$NAME" -v "$VERSION" --all 2>/dev/null || true
        fi
        ;;
esac

exit 0
PRERM

chmod 0755 "$WORK/$PKG/DEBIAN/postinst" "$WORK/$PKG/DEBIAN/prerm"

# Build .deb
OUT_DIR="$REPO_ROOT/dist"
mkdir -p "$OUT_DIR"
dpkg-deb --build "$WORK/$PKG" "$OUT_DIR/${PKG}.deb"

echo "Built $OUT_DIR/${PKG}.deb"
