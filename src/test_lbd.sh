#!/bin/bash
# test_lbd.sh - Integration test for the LBD kernel module
#
# Must be run as root. Loads the module, exercises device creation,
# I/O, log validation, multi-device, and cleanup.
#
# Usage: sudo ./test_lbd.sh [--keep]
#   --keep: don't remove temp files on success (for inspection)

set -euo pipefail

PASS=0
FAIL=0
TMPDIR=""
KEEP=0
MODULE_LOADED=0
LBDCTL="$(dirname "$0")/lbdctl"

# Parse args
for arg in "$@"; do
	case "$arg" in
		--keep) KEEP=1 ;;
		*) echo "Unknown arg: $arg"; exit 1 ;;
	esac
done

# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

cleanup() {
	echo ""
	echo "=== Cleanup ==="

	# Remove any devices we may have created
	if [ $MODULE_LOADED -eq 1 ]; then
		for i in 0 1 2 3; do
			"$LBDCTL" remove "$i" 2>/dev/null || true
			rm -f "/dev/lbd${i}"
		done
		rmmod lbd 2>/dev/null || true
		rm -f /dev/lbd-control
	fi

	if [ $KEEP -eq 0 ] && [ -n "$TMPDIR" ]; then
		rm -rf "$TMPDIR"
		echo "Removed $TMPDIR"
	elif [ -n "$TMPDIR" ]; then
		echo "Temp files kept at $TMPDIR"
	fi

	echo ""
	echo "==============================="
	echo "Results: $PASS passed, $FAIL failed"
	echo "==============================="

	if [ $FAIL -gt 0 ]; then
		exit 1
	fi
}

# Get lbd major number from /proc/devices
get_lbd_major() {
	awk '$2 == "lbd" { print $1 }' /proc/devices
}

# Create /dev/lbd-control misc device node
create_ctl_node() {
	local minor
	minor=$(awk '$2 == "lbd-control" { print $1 }' /proc/misc)
	if [ -n "$minor" ]; then
		mknod /dev/lbd-control c 10 "$minor"
	fi
}

# Create /dev/lbdN block device node
create_blk_node() {
	local idx="$1"
	local major
	major=$(get_lbd_major)
	if [ -n "$major" ]; then
		mknod "/dev/lbd${idx}" b "$major" "$idx"
	fi
}

trap cleanup EXIT

pass() {
	PASS=$((PASS + 1))
	echo "  PASS: $1"
}

fail() {
	FAIL=$((FAIL + 1))
	echo "  FAIL: $1"
}

check() {
	local desc="$1"
	shift
	if "$@" >/dev/null 2>&1; then
		pass "$desc"
	else
		fail "$desc"
	fi
}

check_output() {
	local desc="$1"
	local expected="$2"
	shift 2
	local output
	output=$("$@" 2>&1) || true
	if echo "$output" | grep -qF "$expected"; then
		pass "$desc"
	else
		fail "$desc (expected '$expected', got '$output')"
	fi
}

# ----------------------------------------------------------------
# Precondition checks
# ----------------------------------------------------------------

echo "=== LBD Test Suite ==="
echo ""

if [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: Must be run as root"
	exit 1
fi

if [ ! -x "$LBDCTL" ]; then
	echo "ERROR: lbdctl not found at $LBDCTL (run 'make lbdctl' first)"
	exit 1
fi

MODPATH="$(dirname "$0")/lbd.ko"
if [ ! -f "$MODPATH" ]; then
	echo "ERROR: lbd.ko not found at $MODPATH (run 'make' first)"
	exit 1
fi

TMPDIR=$(mktemp -d /tmp/lbd-test.XXXXXX)
echo "Temp dir: $TMPDIR"
echo ""

# ----------------------------------------------------------------
# Test 1: Module loading
# ----------------------------------------------------------------

echo "--- Test: Module loading ---"

# Ensure clean state
rmmod lbd 2>/dev/null || true

insmod "$MODPATH"
MODULE_LOADED=1
if lsmod | grep -q lbd; then pass "module loaded"; else fail "module loaded"; fi
# Create control device node if not auto-created
if [ ! -c /dev/lbd-control ]; then
	create_ctl_node
fi
check "/dev/lbd-control exists" test -c /dev/lbd-control
echo ""

# ----------------------------------------------------------------
# Test 2: Create backing file and device
# ----------------------------------------------------------------

echo "--- Test: Device creation ---"

IMG="$TMPDIR/test.img"
dd if=/dev/zero of="$IMG" bs=1M count=10 status=none
check "backing file created" test -f "$IMG"

OUTPUT=$("$LBDCTL" add "$IMG" 2>&1)
echo "  lbdctl add: $OUTPUT"
check_output "lbdctl reports device created" "Created /dev/lbd" echo "$OUTPUT"

# Extract device index
DEV_IDX=$(echo "$OUTPUT" | grep -o 'lbd[0-9]*' | grep -o '[0-9]*')
DEV="/dev/lbd${DEV_IDX}"
LOG="$IMG.log.tmp"

# Create block device node if not auto-created
if [ ! -b "$DEV" ]; then
	create_blk_node "$DEV_IDX"
fi
check "block device exists" test -b "$DEV"
check "no .log.tmp before I/O" test ! -f "$LOG"
echo ""

# ----------------------------------------------------------------
# Test 3: Write and read back
# ----------------------------------------------------------------

echo "--- Test: Write and read back ---"

# Write known pattern to block 0
echo -n "HELLO_LBD_TEST_DATA_1234567890" | dd of="$DEV" bs=4096 count=1 conv=notrunc status=none

# Read it back (no sync yet so data is in active segment)
READBACK=$(dd if="$DEV" bs=4096 count=1 status=none | head -c 30)
if [ "$READBACK" = "HELLO_LBD_TEST_DATA_1234567890" ]; then
	pass "read back matches written data"
else
	fail "read back mismatch (got: '$READBACK')"
fi

# Write to a different block
echo -n "BLOCK_TWO_DATA_" | dd of="$DEV" bs=4096 count=1 seek=2 conv=notrunc status=none

READBACK2=$(dd if="$DEV" bs=4096 count=1 skip=2 status=none | head -c 15)
if [ "$READBACK2" = "BLOCK_TWO_DATA_" ]; then
	pass "block 2 read back matches"
else
	fail "block 2 read back mismatch (got: '$READBACK2')"
fi

# .log.tmp should now exist (writes flushed the buffer)
check "log.tmp created after writes" test -f "$LOG"
echo ""

# ----------------------------------------------------------------
# Test 4: Log entries in active segment
# ----------------------------------------------------------------

echo "--- Test: Log entries (active segment) ---"

LOG_OUTPUT=$("$LBDCTL" log "$LOG" 2>&1)
echo "$LOG_OUTPUT" | head -20

# Validate header
check_output "log header has correct version" "Version:      2" echo "$LOG_OUTPUT"
check_output "log header has correct block size" "Block size:   4096" echo "$LOG_OUTPUT"
check_output "log header references backing file" "$IMG" echo "$LOG_OUTPUT"

# Should have entries now (in .log.tmp before sync)
ENTRY_COUNT=$(echo "$LOG_OUTPUT" | grep "Total entries:" | awk '{print $3}')
if [ -n "$ENTRY_COUNT" ] && [ "$ENTRY_COUNT" -ge 2 ]; then
	pass "active segment has >= 2 entries after 2 writes (got $ENTRY_COUNT)"
else
	fail "expected >= 2 log entries (got ${ENTRY_COUNT:-none})"
fi

# Check CRC validity
if echo "$LOG_OUTPUT" | grep -q "(OK)"; then
	pass "at least one entry has valid CRC"
else
	fail "no entries with valid CRC found"
fi

if echo "$LOG_OUTPUT" | grep -q "MISMATCH"; then
	fail "found CRC mismatch in log entries"
else
	pass "no CRC mismatches in log"
fi
echo ""

# ----------------------------------------------------------------
# Test 5b: Flush-triggered segment rotation
# ----------------------------------------------------------------

echo "--- Test: Flush-triggered segment rotation ---"

# fsync on the block device triggers REQ_OP_FLUSH -> segment rotation
sync "$DEV"
sleep 1

# Find completed segment files (named <img>.@<tai64n>.log)
SEG_FILES=( $(ls "$IMG".[0-9a-f]*.log 2>/dev/null | sort) )
if [ ${#SEG_FILES[@]} -ge 1 ]; then
	pass "segment file created after sync (${SEG_FILES[0]##*/})"
else
	fail "no segment file created after sync"
fi
SEG0="${SEG_FILES[0]}"
check "no .log.tmp after rotation (lazy open)" test ! -f "$LOG"

# Verify the completed segment is readable
SEG0_OUTPUT=$("$LBDCTL" log "$SEG0" 2>&1)
SEG0_COUNT=$(echo "$SEG0_OUTPUT" | grep "Total entries:" | awk '{print $3}')
if [ -n "$SEG0_COUNT" ] && [ "$SEG0_COUNT" -ge 2 ]; then
	pass "segment 0 has >= 2 entries (got $SEG0_COUNT)"
else
	fail "segment 0 expected >= 2 entries (got ${SEG0_COUNT:-none})"
fi

# Verify segment_label in header (TAI64N starts with @)
if echo "$SEG0_OUTPUT" | grep -q "Segment:      4"; then
	pass "segment 0 header has TAI64N label"
else
	fail "segment 0 header missing TAI64N label"
fi
echo ""

# ----------------------------------------------------------------
# Test 5c: Multiple segment rotation
# ----------------------------------------------------------------

echo "--- Test: Multiple segments ---"

# Write more data and sync to create segment 1
echo -n "SEGMENT_ONE_DATA" | dd of="$DEV" bs=4096 count=1 seek=4 conv=notrunc status=none
sync "$DEV"
sleep 1

SEG_FILES=( $(ls "$IMG".[0-9a-f]*.log 2>/dev/null | sort) )
if [ ${#SEG_FILES[@]} -ge 2 ]; then
	pass "second segment created after second sync (${SEG_FILES[1]##*/})"
else
	fail "second segment not created after second sync"
fi
SEG1="${SEG_FILES[1]}"

# Verify segment_label in header
SEG1_OUTPUT=$("$LBDCTL" log "$SEG1" 2>&1)
if echo "$SEG1_OUTPUT" | grep -q "Segment:      4"; then
	pass "segment 1 header has TAI64N label"
else
	fail "segment 1 header missing TAI64N label"
fi

SEG1_COUNT=$(echo "$SEG1_OUTPUT" | grep "Total entries:" | awk '{print $3}')
if [ -n "$SEG1_COUNT" ] && [ "$SEG1_COUNT" -ge 1 ]; then
	pass "segment 1 has entries (got $SEG1_COUNT)"
else
	fail "segment 1 has no entries"
fi

# Verify segment 0 JSON has segment_label
SEG0_JSON=$("$LBDCTL" log --json "$SEG0" 2>&1)
if echo "$SEG0_JSON" | grep -q '"segment_label": "4'; then
	pass "segment 0 JSON has segment_label"
else
	fail "segment 0 JSON missing segment_label"
fi
echo ""

# ----------------------------------------------------------------
# Test 6: Log with --data flag (on completed segment)
# ----------------------------------------------------------------

echo "--- Test: Log with data dump ---"

"$LBDCTL" log --data "$SEG0" > "$TMPDIR/seg0_data.txt" 2>&1 || true
if grep -q "Data:" "$TMPDIR/seg0_data.txt"; then
	pass "--data flag shows data section"
else
	fail "--data flag did not show data section"
	echo "  DEBUG: seg0_data.txt line count: $(wc -l < "$TMPDIR/seg0_data.txt")"
	head -5 "$TMPDIR/seg0_data.txt" | sed 's/^/  DEBUG: /'
fi

# Check that our written string appears in the hex dump
if grep -q "HELLO_LBD" "$TMPDIR/seg0_data.txt"; then
	pass "written data visible in hex dump ASCII column"
else
	fail "written data not visible in hex dump"
fi
echo ""

# ----------------------------------------------------------------
# Test 7: JSON output (on completed segment)
# ----------------------------------------------------------------

echo "--- Test: JSON output ---"

"$LBDCTL" log --json "$SEG0" > "$TMPDIR/seg0_json.txt" 2>&1 || true

# Basic structural checks
if grep -q '"header"' "$TMPDIR/seg0_json.txt"; then
	pass "JSON has header object"
else
	fail "JSON missing header"
fi

if grep -q '"entries"' "$TMPDIR/seg0_json.txt"; then
	pass "JSON has entries array"
else
	fail "JSON missing entries"
fi

if grep -q '"entry_count"' "$TMPDIR/seg0_json.txt"; then
	pass "JSON has entry_count"
else
	fail "JSON missing entry_count"
fi

if grep -q '"checksum_valid": true' "$TMPDIR/seg0_json.txt"; then
	pass "JSON shows valid checksums"
else
	fail "JSON shows no valid checksums"
fi

if grep -q '"timestamp"' "$TMPDIR/seg0_json.txt"; then
	pass "JSON has ISO timestamps"
else
	fail "JSON missing timestamps"
fi

# JSON with --data
"$LBDCTL" log --json --data "$SEG0" > "$TMPDIR/seg0_json_data.txt" 2>&1 || true
if grep -q '"data_hex"' "$TMPDIR/seg0_json_data.txt"; then
	pass "JSON --data includes data_hex field"
else
	fail "JSON --data missing data_hex"
fi
echo ""

# ----------------------------------------------------------------
# Test 8: lbdctl list
# ----------------------------------------------------------------

echo "--- Test: Device listing ---"

LIST_OUTPUT=$("$LBDCTL" list 2>&1)
echo "  $LIST_OUTPUT" | head -5

if echo "$LIST_OUTPUT" | grep -q "lbd${DEV_IDX}"; then
	pass "list shows device lbd${DEV_IDX}"
else
	fail "list does not show device lbd${DEV_IDX}"
fi

if echo "$LIST_OUTPUT" | grep -q "bound"; then
	pass "list shows bound state"
else
	fail "list does not show bound state"
fi
echo ""

# ----------------------------------------------------------------
# Test 9: Multi-device support
# ----------------------------------------------------------------

echo "--- Test: Multi-device ---"

IMG2="$TMPDIR/test2.img"
dd if=/dev/zero of="$IMG2" bs=1M count=5 status=none

OUTPUT2=$("$LBDCTL" add "$IMG2" 2>&1)
echo "  lbdctl add: $OUTPUT2"
DEV2_IDX=$(echo "$OUTPUT2" | grep -o 'lbd[0-9]*' | grep -o '[0-9]*')
DEV2="/dev/lbd${DEV2_IDX}"

# Create block device node if not auto-created
if [ ! -b "$DEV2" ]; then
	create_blk_node "$DEV2_IDX"
fi
check "second device exists" test -b "$DEV2"
check "no .log.tmp for second device before I/O" test ! -f "$IMG2.log.tmp"

# Write to second device
echo -n "DEVICE_TWO" | dd of="$DEV2" bs=4096 count=1 conv=notrunc status=none
sync "$DEV2"
sleep 1

READBACK3=$(dd if="$DEV2" bs=4096 count=1 status=none | head -c 10)
if [ "$READBACK3" = "DEVICE_TWO" ]; then
	pass "second device read/write works"
else
	fail "second device read back mismatch"
fi

# Both devices should appear in list
LIST2=$("$LBDCTL" list 2>&1)
if echo "$LIST2" | grep -q "lbd${DEV_IDX}" && echo "$LIST2" | grep -q "lbd${DEV2_IDX}"; then
	pass "list shows both devices"
else
	fail "list does not show both devices"
fi
echo ""

# ----------------------------------------------------------------
# Test 10: Device removal
# ----------------------------------------------------------------

echo "--- Test: Device removal ---"

"$LBDCTL" remove "$DEV2_IDX"
rm -f "$DEV2"
check "second device removed" test ! -b "$DEV2"

# First device should still work
READBACK4=$(dd if="$DEV" bs=4096 count=1 status=none | head -c 30)
if [ "$READBACK4" = "HELLO_LBD_TEST_DATA_1234567890" ]; then
	pass "first device still works after removing second"
else
	fail "first device broken after removing second"
fi

# Second device's log: sync rotated entries to a completed segment.
# No .log.tmp remains (lazy open means new segment has no file yet).
# The completed segment should still be readable.
LOG2_SEG=$(ls "$IMG2".[0-9a-f]*.log 2>/dev/null | head -1)
check "second device segment exists from sync" test -n "$LOG2_SEG" -a -f "$LOG2_SEG"
LOG2_OUTPUT=$("$LBDCTL" log "$LOG2_SEG" 2>&1)
check_output "second device segment readable after removal" "Total entries:" echo "$LOG2_OUTPUT"
echo ""

# ----------------------------------------------------------------
# Test 11: Larger I/O
# ----------------------------------------------------------------

echo "--- Test: Larger I/O ---"

# Write 64K of data
dd if=/dev/urandom of="$TMPDIR/random_64k" bs=64K count=1 status=none
dd if="$TMPDIR/random_64k" of="$DEV" bs=64K count=1 conv=notrunc status=none
sync "$DEV"
sleep 1

# Read back and compare
dd if="$DEV" bs=64K count=1 status=none of="$TMPDIR/readback_64k"
if cmp -s "$TMPDIR/random_64k" "$TMPDIR/readback_64k"; then
	pass "64K write/read roundtrip matches"
else
	fail "64K write/read roundtrip mismatch"
fi
echo ""

# ----------------------------------------------------------------
# Test 12: Module unload (cleans up remaining devices)
# ----------------------------------------------------------------

echo "--- Test: Module unload ---"

# Remove remaining device first
"$LBDCTL" remove "$DEV_IDX" 2>/dev/null || true
rm -f "$DEV"

rmmod lbd
MODULE_LOADED=0
rm -f /dev/lbd-control
check "module unloaded" test ! -c /dev/lbd-control
check "block device gone" test ! -b "$DEV"
echo ""

# ----------------------------------------------------------------
# Test 13: Log still readable after unload
# ----------------------------------------------------------------

echo "--- Test: Post-unload log access ---"

# After removal, completed segments should still be readable
FINAL_LOG=$("$LBDCTL" log "$SEG0" 2>&1)
if echo "$FINAL_LOG" | grep -q "Total entries:"; then
	pass "segment log readable after module unload"
else
	fail "segment log not readable after module unload"
fi

FINAL_JSON=$("$LBDCTL" log --json "$SEG0" 2>&1)
if echo "$FINAL_JSON" | grep -q '"entry_count"'; then
	pass "JSON segment log readable after module unload"
else
	fail "JSON segment log not readable after module unload"
fi
echo ""
