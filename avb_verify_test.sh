#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# (C) Copyright 2026
# Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
#
# Integration tests for avb_verify
set -euo pipefail

AVBTOOL="python3 avb/avbtool.py"
VERIFY="${avb_verify:-./build/avb_verify}"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

pass=0
fail=0

ok() {
    echo "  PASS  $1"
    pass=$((pass + 1))
}

nok() {
    echo "  FAIL  $1"
    fail=$((fail + 1))
}

echo "=== Setting up test fixtures ==="

# Generate test keys
openssl genrsa -out "$TMPDIR/key.pem" 4096 2>/dev/null
openssl genrsa -out "$TMPDIR/wrong_key.pem" 4096 2>/dev/null

# Extract AVB public keys
$AVBTOOL extract_public_key --key "$TMPDIR/key.pem" --output "$TMPDIR/pubkey.bin"
$AVBTOOL extract_public_key --key "$TMPDIR/wrong_key.pem" --output "$TMPDIR/wrong_pubkey.bin"

# Create a small ext4 image (4MB filesystem, 8MB partition)
truncate -s 4M "$TMPDIR/system.img"
mkfs.ext4 -q "$TMPDIR/system.img"

# Sign with add_hashtree_footer
$AVBTOOL add_hashtree_footer \
    --image "$TMPDIR/system.img" \
    --partition_name system \
    --partition_size 8388608 \
    --algorithm SHA256_RSA4096 \
    --hash_algorithm sha256 \
    --key "$TMPDIR/key.pem" \
    --do_not_generate_fec

echo ""
echo "=== Running tests ==="

# 1. Basic verification succeeds
if OUT=$("$VERIFY" "$TMPDIR/system.img" "$TMPDIR/pubkey.bin" 2>&1); then
    ok "basic verification"
else
    nok "basic verification"
fi

# 2. Output contains expected fields
echo "$OUT" | grep -q "Verification:  OK" && ok "output has Verification OK" || nok "output has Verification OK"
echo "$OUT" | grep -q "Algorithm:.*SHA256_RSA4096" && ok "output has algorithm" || nok "output has algorithm"
echo "$OUT" | grep -q "Partition:.*system" && ok "output has partition name" || nok "output has partition name"
echo "$OUT" | grep -q "^  0 .* verity " && ok "output has dm table" || nok "output has dm table"

# 3. --dm-table mode outputs raw table only
DM_OUT=$("$VERIFY" --dm-table "$TMPDIR/system.img" "$TMPDIR/pubkey.bin")
DM_LINES=$(echo "$DM_OUT" | wc -l)
[[ $DM_LINES -eq 1 ]] && ok "--dm-table outputs single line" || nok "--dm-table outputs single line"
echo "$DM_OUT" | grep -q "^0 .* verity " && ok "--dm-table starts with 0" || nok "--dm-table starts with 0"

# 4. --dm-table with device path substitution
"$VERIFY" --dm-table "$TMPDIR/system.img" "$TMPDIR/pubkey.bin" /dev/sda1 2>/dev/null | grep -q "/dev/sda1" \
    && ok "--dm-table device substitution" || nok "--dm-table device substitution"

# 5. Wrong key is rejected
"$VERIFY" "$TMPDIR/system.img" "$TMPDIR/wrong_pubkey.bin" >/dev/null 2>&1 \
    && nok "wrong key rejected" || ok "wrong key rejected"

# 6. Corrupted image is rejected
cp "$TMPDIR/system.img" "$TMPDIR/corrupt.img"
# Read footer to find VBMeta offset, then corrupt its signature
python3 -c "
import struct
path = '$TMPDIR/corrupt.img'
with open(path, 'r+b') as f:
    f.seek(-64, 2)
    footer = f.read(64)
    vbmeta_off = struct.unpack('>Q', footer[20:28])[0]
    f.seek(vbmeta_off + 256)
    f.write(b'\\xff' * 64)
"
"$VERIFY" "$TMPDIR/corrupt.img" "$TMPDIR/pubkey.bin" >/dev/null 2>&1 \
    && nok "corrupted image rejected" || ok "corrupted image rejected"

# 7. Truncated file is rejected
truncate -s 32 "$TMPDIR/tiny.img"
"$VERIFY" "$TMPDIR/tiny.img" "$TMPDIR/pubkey.bin" >/dev/null 2>&1 \
    && nok "truncated file rejected" || ok "truncated file rejected"

# 8. Missing arguments shows usage
"$VERIFY" >/dev/null 2>&1 \
    && nok "no args shows usage" || ok "no args shows usage"

# 9. Nonexistent image file
"$VERIFY" "$TMPDIR/nonexistent.img" "$TMPDIR/pubkey.bin" >/dev/null 2>&1 \
    && nok "nonexistent image rejected" || ok "nonexistent image rejected"

# 10. Nonexistent key file
"$VERIFY" "$TMPDIR/system.img" "$TMPDIR/nonexistent.bin" >/dev/null 2>&1 \
    && nok "nonexistent key rejected" || ok "nonexistent key rejected"

echo ""
echo "=== Results: $pass passed, $fail failed ==="
exit "$fail"
