#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC_DIR="$REPO_ROOT/src"
SPEC="$SCRIPT_DIR/lbd-dkms.spec"

NAME="lbd"
VERSION="0.1.0"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Set up rpmbuild tree
mkdir -p "$WORK"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Source files to package (kernel module only, no build artifacts)
SRC_FILES=(
    Makefile dkms.conf
    lbd_main.c lbd.h
    lbd_qcow2.c lbd_qcow2.h lbd_qcow2_format.h
    lbdctl.c
    cbor_enc.h cbor_dec.h
    lz4_kcompat.h
)

# Create source tarball
TAR_DIR="$WORK/lbd-$VERSION"
mkdir -p "$TAR_DIR/lz4"

for f in "${SRC_FILES[@]}"; do
    cp "$SRC_DIR/$f" "$TAR_DIR/$f"
done
cp "$SRC_DIR/lz4/lz4.c" "$SRC_DIR/lz4/lz4.h" "$TAR_DIR/lz4/"

tar czf "$WORK/SOURCES/lbd-$VERSION.tar.gz" -C "$WORK" "lbd-$VERSION"

# Build RPM
OUT_DIR="$REPO_ROOT/dist"
mkdir -p "$OUT_DIR"

rpmbuild -bb \
    --define "_topdir $WORK" \
    --define "version $VERSION" \
    "$SPEC"

cp "$WORK"/RPMS/noarch/*.rpm "$OUT_DIR/"

echo "Built $(ls "$OUT_DIR"/lbd-dkms-*.rpm)"
