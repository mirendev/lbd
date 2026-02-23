#!/bin/bash
# test-compat.sh — Docker-based kernel compat build matrix for lbd
#
# Tests the kernel module against multiple kernel versions using:
#   - Fedora 35–43 (kernel-devel from each release)
#   - Ubuntu 22.04 HWE kernels (5.15, 5.19, 6.2, 6.5, 6.8)
#   - Ubuntu 24.04 HWE kernels (6.8, 6.11, 6.14, 6.17)
#   - Ubuntu 25.10
#
# Usage:
#   ./test-compat.sh              # run all sequentially
#   ./test-compat.sh --parallel   # run all in parallel
#   ./test-compat.sh fedora:41    # run one image (default kernel)
#   ./test-compat.sh ubuntu:22.04/5.15  # run one Ubuntu HWE kernel

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"

# Fedora releases — each gets its latest kernel-devel
FEDORA_IMAGES=(
	"fedora:35"   # kernel ~5.14
	"fedora:36"   # kernel ~5.17
	"fedora:37"   # kernel ~6.0
	"fedora:38"   # kernel ~6.2
	"fedora:39"   # kernel ~6.5
	"fedora:40"   # kernel ~6.8
	"fedora:41"   # kernel ~6.11
	"fedora:42"   # kernel ~6.13
	"fedora:43"
)

# Ubuntu HWE entries: "image/major.minor" — installs a specific HWE kernel
UBUNTU_HWE=(
	"ubuntu:22.04/5.15"
	"ubuntu:22.04/5.19"
	"ubuntu:22.04/6.2"
	"ubuntu:22.04/6.5"
	"ubuntu:22.04/6.8"
	"ubuntu:24.04/6.8"
	"ubuntu:24.04/6.11"
	"ubuntu:24.04/6.14"
	"ubuntu:24.04/6.17"
	"ubuntu:25.10"
)

ALL_TARGETS=("${FEDORA_IMAGES[@]}" "${UBUNTU_HWE[@]}")

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

build_fedora() {
	local image="$1"

	docker run --rm \
		-v "$SRC_DIR:/build/src:ro" \
		"$image" \
		bash -c '
			set -e
			dnf install -y kernel-devel gcc make 2>&1 | tail -3

			KDIR=$(ls -d /usr/src/kernels/* 2>/dev/null | head -1)
			if [ -z "$KDIR" ]; then
				echo "ERROR: No kernel-devel headers found"
				exit 1
			fi

			echo "Kernel headers: $KDIR"
			echo "Kernel version: $(basename $KDIR)"

			mkdir -p /build/obj
			cp -a /build/src/* /build/obj/

			make -C "$KDIR" M=/build/obj KBUILD_MODPOST_WARN=1 modules 2>&1
			echo "BUILD OK"
		' 2>&1
}

# Build against a specific Ubuntu HWE kernel version.
# $1 = docker image (e.g. ubuntu:24.04)
# $2 = kernel major.minor to target (e.g. 6.14), or empty for default
build_ubuntu() {
	local image="$1"
	local target_ver="${2:-}"

	docker run --rm \
		-v "$SRC_DIR:/build/src:ro" \
		"$image" \
		bash -c "
			set -e
			export DEBIAN_FRONTEND=noninteractive
			apt-get update -qq 2>&1 | tail -1

			TARGET_VER='$target_ver'
			if [ -n \"\$TARGET_VER\" ]; then
				# Find the exact header package for this major.minor
				PKG=\$(apt-cache search linux-headers | \
				       grep -oP \"linux-headers-\${TARGET_VER}\\.\\d+-\\d+(?=-generic)\" | \
				       sort -V | tail -1)
				if [ -z \"\$PKG\" ]; then
					echo \"ERROR: No headers found for kernel \$TARGET_VER\"
					exit 1
				fi
				apt-get install -y -qq \${PKG}-generic gcc make 2>&1 | tail -3
			else
				apt-get install -y -qq linux-headers-generic gcc make 2>&1 | tail -3
			fi

			KDIR=\$(ls -d /usr/src/linux-headers-*-generic 2>/dev/null | sort -V | tail -1)

			# HWE kernels may require a different gcc version (e.g. gcc-12
			# on 22.04). Detect from the kernel Makefile and install if needed.
			NEED_GCC=\$(grep -oP 'gcc-\\d+' \"\$KDIR\"/Makefile | head -1 || true)
			if [ -n \"\$NEED_GCC\" ] && ! command -v \"\$NEED_GCC\" >/dev/null 2>&1; then
				apt-get install -y -qq \"\$NEED_GCC\" 2>&1 | tail -1
			fi
			if [ -z \"\$KDIR\" ]; then
				echo 'ERROR: No kernel headers found'
				exit 1
			fi

			echo \"Kernel headers: \$KDIR\"
			echo \"Kernel version: \$(basename \$KDIR)\"

			mkdir -p /build/obj
			cp -a /build/src/* /build/obj/

			make -C \"\$KDIR\" M=/build/obj KBUILD_MODPOST_WARN=1 modules 2>&1
			echo 'BUILD OK'
		" 2>&1
}

# Dispatch a single build target to the right builder.
# Target format: "fedora:N", "ubuntu:XX.YY", or "ubuntu:XX.YY/M.m"
build_target() {
	local target="$1"
	local logfile="$2"

	if [[ "$target" == fedora:* ]]; then
		build_fedora "$target" >"$logfile" 2>&1
	elif [[ "$target" == ubuntu:* ]]; then
		local image="${target%%/*}"
		local ver=""
		if [[ "$target" == */* ]]; then
			ver="${target#*/}"
		fi
		build_ubuntu "$image" "$ver" >"$logfile" 2>&1
	else
		echo "Unknown target: $target" >"$logfile"
		return 1
	fi
}

# ----------------------------------------------------------------
# Parse arguments
# ----------------------------------------------------------------
PARALLEL=false
SINGLE_TARGET=""

for arg in "$@"; do
	case "$arg" in
		--parallel)
			PARALLEL=true
			;;
		*)
			SINGLE_TARGET="$arg"
			;;
	esac
done

if [ -n "$SINGLE_TARGET" ]; then
	ALL_TARGETS=("$SINGLE_TARGET")
fi

# ----------------------------------------------------------------
# Run builds
# ----------------------------------------------------------------
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

declare -A PIDS

if $PARALLEL; then
	echo "Running ${#ALL_TARGETS[@]} builds in parallel..."
	for target in "${ALL_TARGETS[@]}"; do
		logfile="$TMPDIR/${target//[:\/]/_}.log"
		build_target "$target" "$logfile" &
		PIDS["$target"]=$!
	done

	PASS=0
	FAIL=0
	for target in "${ALL_TARGETS[@]}"; do
		if wait "${PIDS[$target]}" 2>/dev/null; then
			echo -e "${GREEN}PASS${NC} $target"
			PASS=$((PASS + 1))
		else
			echo -e "${RED}FAIL${NC} $target"
			FAIL=$((FAIL + 1))
			logfile="$TMPDIR/${target//[:\/]/_}.log"
			echo "  --- last 20 lines of build log ---"
			tail -20 "$logfile" | sed 's/^/  /'
		fi
	done
else
	PASS=0
	FAIL=0
	for target in "${ALL_TARGETS[@]}"; do
		logfile="$TMPDIR/${target//[:\/]/_}.log"
		if build_target "$target" "$logfile"; then
			echo -e "${GREEN}PASS${NC} $target"
			PASS=$((PASS + 1))
		else
			echo -e "${RED}FAIL${NC} $target"
			FAIL=$((FAIL + 1))
			echo "  --- last 30 lines of build log ---"
			tail -30 "$logfile" | sed 's/^/  /'
		fi
	done
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed out of ${#ALL_TARGETS[@]} ==="

if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
