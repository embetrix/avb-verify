#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# (C) Copyright 2026
# Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
#
# Integration tests for avb_verify
set -euo pipefail

AVBTOOL="python3 avb/avbtool.py"
VERIFY="${avb_verify:-./build/avb_verify}"
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

# Check for required tools upfront to fail fast with a clear message
for tool in openssl xxd keyctl mkfs.ext4 mkfs.erofs mksquashfs; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool '$tool' not found" >&2
        exit 1
    fi
done

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
openssl genrsa -out "$TEST_DIR/key.pem" 4096 2>/dev/null
openssl genrsa -out "$TEST_DIR/wrong_key.pem" 4096 2>/dev/null

# Extract AVB public keys
$AVBTOOL extract_public_key --key "$TEST_DIR/key.pem" --output "$TEST_DIR/pubkey.bin"
$AVBTOOL extract_public_key --key "$TEST_DIR/wrong_key.pem" --output "$TEST_DIR/wrong_pubkey.bin"

# Create a small ext4 image (4MB filesystem)
truncate -s 4M "$TEST_DIR/system.img"
mkfs.ext4 -q "$TEST_DIR/system.img"

# Sign with add_hashtree_footer (--partition_size 0 appends footer at end of data)
$AVBTOOL add_hashtree_footer \
    --image "$TEST_DIR/system.img" \
    --partition_name system \
    --partition_size 0 \
    --algorithm SHA256_RSA4096 \
    --hash_algorithm sha256 \
    --key "$TEST_DIR/key.pem" \
    --do_not_generate_fec

# Extract the root hash from the signed image, create PKCS#7 signature,
# and rebuild with the signature embedded as a property.
ROOT_HASH=$($AVBTOOL info_image --image "$TEST_DIR/system.img" 2>/dev/null \
    | sed -n 's/.*Root Digest:[[:space:]]*//p')
if [ -z "$ROOT_HASH" ]; then
    echo "ERROR: failed to extract root hash from system.img" >&2
    exit 1
fi
echo -n "$ROOT_HASH" | xxd -r -p > "$TEST_DIR/roothash.bin"

# Create a self-signed certificate for root hash signing
openssl req -x509 -newkey rsa:4096 -keyout "$TEST_DIR/sig_key.pem" \
    -out "$TEST_DIR/sig_cert.pem" -days 365 -nodes \
    -subj "/CN=roothash-signer" 2>/dev/null

# Create PKCS#7 detached signature of the root hash
openssl smime -sign -nocerts -noattr -binary \
    -in "$TEST_DIR/roothash.bin" -inkey "$TEST_DIR/sig_key.pem" \
    -signer "$TEST_DIR/sig_cert.pem" \
    -outform der -out "$TEST_DIR/roothash.p7s"

# Create a second image with the signature embedded as a property
cp "$TEST_DIR/system.img" "$TEST_DIR/system_sig.img"
$AVBTOOL erase_footer --image "$TEST_DIR/system_sig.img" 2>/dev/null
$AVBTOOL add_hashtree_footer \
    --image "$TEST_DIR/system_sig.img" \
    --partition_name system \
    --partition_size 0 \
    --algorithm SHA256_RSA4096 \
    --hash_algorithm sha256 \
    --key "$TEST_DIR/key.pem" \
    --do_not_generate_fec \
    --prop_from_file roothash_sig:"$TEST_DIR/roothash.p7s"

# Create a small erofs image
mkdir -p "$TEST_DIR/erofs_root"
echo "erofs test" > "$TEST_DIR/erofs_root/hello.txt"
mkfs.erofs "$TEST_DIR/erofs.img" "$TEST_DIR/erofs_root" 2>/dev/null

$AVBTOOL add_hashtree_footer \
    --image "$TEST_DIR/erofs.img" \
    --partition_name erofs_part \
    --partition_size 0 \
    --algorithm SHA256_RSA4096 \
    --hash_algorithm sha256 \
    --key "$TEST_DIR/key.pem" \
    --do_not_generate_fec

# Create a small squashfs image
mkdir -p "$TEST_DIR/squashfs_root"
echo "squashfs test" > "$TEST_DIR/squashfs_root/hello.txt"
mksquashfs "$TEST_DIR/squashfs_root" "$TEST_DIR/squashfs.img" -quiet -noappend

$AVBTOOL add_hashtree_footer \
    --image "$TEST_DIR/squashfs.img" \
    --partition_name squashfs_part \
    --partition_size 0 \
    --algorithm SHA256_RSA4096 \
    --hash_algorithm sha256 \
    --key "$TEST_DIR/key.pem" \
    --do_not_generate_fec

echo ""
echo "=== Running tests ==="

# 1. Basic verification succeeds
if OUT=$("$VERIFY" -d "$TEST_DIR/system.img" -k "$TEST_DIR/pubkey.bin" 2>&1); then
    ok "basic verification"
else
    nok "basic verification"
fi

# 2. Output contains expected fields
echo "$OUT" | grep -q "Verification:  OK" && ok "output has Verification OK" || nok "output has Verification OK"
echo "$OUT" | grep -q "Algorithm:.*SHA256_RSA4096" && ok "output has algorithm" || nok "output has algorithm"
echo "$OUT" | grep -q "Partition:.*system" && ok "output has partition name" || nok "output has partition name"
echo "$OUT" | grep -q "^  0 .* verity " && ok "output has dm table" || nok "output has dm table"

# 3. -t/--dm-table mode outputs raw table only
DM_OUT=$("$VERIFY" -t -d "$TEST_DIR/system.img" -k "$TEST_DIR/pubkey.bin" 2>/dev/null)
DM_LINES=$(echo "$DM_OUT" | wc -l)
[[ $DM_LINES -eq 1 ]] && ok "--dm-table outputs single line" || nok "--dm-table outputs single line"
echo "$DM_OUT" | grep -q "^0 .* verity " && ok "--dm-table starts with 0" || nok "--dm-table starts with 0"

# 4. Wrong key is rejected
"$VERIFY" -d "$TEST_DIR/system.img" -k "$TEST_DIR/wrong_pubkey.bin" >/dev/null 2>&1 \
    && nok "wrong key rejected" || ok "wrong key rejected"

# 5. Corrupted image is rejected
cp "$TEST_DIR/system.img" "$TEST_DIR/corrupt.img"
# Read footer to find VBMeta offset, then corrupt its signature
python3 -c "
import struct
path = '$TEST_DIR/corrupt.img'
with open(path, 'r+b') as f:
    f.seek(-64, 2)
    footer = f.read(64)
    vbmeta_off = struct.unpack('>Q', footer[20:28])[0]
    f.seek(vbmeta_off + 256)
    f.write(b'\\xff' * 64)
"
"$VERIFY" -d "$TEST_DIR/corrupt.img" -k "$TEST_DIR/pubkey.bin" >/dev/null 2>&1 \
    && nok "corrupted image rejected" || ok "corrupted image rejected"

# 6. Truncated file is rejected
truncate -s 32 "$TEST_DIR/tiny.img"
"$VERIFY" -d "$TEST_DIR/tiny.img" -k "$TEST_DIR/pubkey.bin" >/dev/null 2>&1 \
    && nok "truncated file rejected" || ok "truncated file rejected"

# 7. Footer scanning: image padded to a larger size (simulates writing to a bigger device)
cp "$TEST_DIR/system.img" "$TEST_DIR/padded.img"
truncate -s 8M "$TEST_DIR/padded.img"
if "$VERIFY" -d "$TEST_DIR/padded.img" -k "$TEST_DIR/pubkey.bin" >/dev/null 2>&1; then
    ok "footer scanning on padded image"
else
    nok "footer scanning on padded image"
fi

# 8. Footer scanning produces no spurious errors on stderr
SCAN_ERR=$("$VERIFY" -d "$TEST_DIR/padded.img" -k "$TEST_DIR/pubkey.bin" 2>&1 >/dev/null)
if echo "$SCAN_ERR" | grep -q "Error:"; then
    nok "footer scan has no errors on stderr"
else
    ok "footer scan has no errors on stderr"
fi

# 9. Missing arguments shows usage
USAGE_OUT=$("$VERIFY" 2>&1 || true)
echo "$USAGE_OUT" | grep -q "Usage" \
    && ok "no args shows usage" || nok "no args shows usage"

# 10. Nonexistent image file
"$VERIFY" -d "$TEST_DIR/nonexistent.img" -k "$TEST_DIR/pubkey.bin" >/dev/null 2>&1 \
    && nok "nonexistent image rejected" || ok "nonexistent image rejected"

# 11. Nonexistent key file
"$VERIFY" -d "$TEST_DIR/system.img" -k "$TEST_DIR/nonexistent.bin" >/dev/null 2>&1 \
    && nok "nonexistent key rejected" || ok "nonexistent key rejected"

# 12. erofs: basic verification
if "$VERIFY" -d "$TEST_DIR/erofs.img" -k "$TEST_DIR/pubkey.bin" 2>/dev/null | grep -q "Verification:  OK"; then
    ok "erofs basic verification"
else
    nok "erofs basic verification"
fi

# 13. erofs: --dm-table output
if "$VERIFY" -t -d "$TEST_DIR/erofs.img" -k "$TEST_DIR/pubkey.bin" 2>/dev/null | grep -q "^0 .* verity "; then
    ok "erofs --dm-table output"
else
    nok "erofs --dm-table output"
fi

# 14. erofs: footer scanning on padded image
cp "$TEST_DIR/erofs.img" "$TEST_DIR/erofs_padded.img"
truncate -s 8M "$TEST_DIR/erofs_padded.img"
if "$VERIFY" -d "$TEST_DIR/erofs_padded.img" -k "$TEST_DIR/pubkey.bin" >/dev/null 2>&1; then
    ok "erofs footer scanning on padded image"
else
    nok "erofs footer scanning on padded image"
fi

# 15. squashfs: basic verification
if "$VERIFY" -d "$TEST_DIR/squashfs.img" -k "$TEST_DIR/pubkey.bin" 2>/dev/null | grep -q "Verification:  OK"; then
    ok "squashfs basic verification"
else
    nok "squashfs basic verification"
fi

# 16. squashfs: --dm-table output
if "$VERIFY" -t -d "$TEST_DIR/squashfs.img" -k "$TEST_DIR/pubkey.bin" 2>/dev/null | grep -q "^0 .* verity "; then
    ok "squashfs --dm-table output"
else
    nok "squashfs --dm-table output"
fi

# 17. squashfs: footer scanning on padded image
cp "$TEST_DIR/squashfs.img" "$TEST_DIR/squashfs_padded.img"
truncate -s 8M "$TEST_DIR/squashfs_padded.img"
if "$VERIFY" -d "$TEST_DIR/squashfs_padded.img" -k "$TEST_DIR/pubkey.bin" >/dev/null 2>&1; then
    ok "squashfs footer scanning on padded image"
else
    nok "squashfs footer scanning on padded image"
fi

# 18. -x: verification succeeds with correct digest
DIGEST=$(sha256sum "$TEST_DIR/pubkey.bin" | cut -d' ' -f1)
if "$VERIFY" -d "$TEST_DIR/system.img" -k "$TEST_DIR/pubkey.bin" -x "$DIGEST" 2>/dev/null | grep -q "Verification:  OK"; then
    ok "-x correct digest"
else
    nok "-x correct digest"
fi

# 19. -x: wrong digest is rejected
WRONG_DIGEST=$(sha256sum "$TEST_DIR/wrong_pubkey.bin" | cut -d' ' -f1)
"$VERIFY" -d "$TEST_DIR/system.img" -k "$TEST_DIR/pubkey.bin" -x "$WRONG_DIGEST" >/dev/null 2>&1 \
    && nok "-x wrong digest rejected" || ok "-x wrong digest rejected"

# 20. -x: invalid hex is rejected
"$VERIFY" -d "$TEST_DIR/system.img" -k "$TEST_DIR/pubkey.bin" -x "not_hex" >/dev/null 2>&1 \
    && nok "-x invalid hex rejected" || ok "-x invalid hex rejected"

# 21. -x without -k is rejected
"$VERIFY" -d "$TEST_DIR/system.img" -x "$DIGEST" >/dev/null 2>&1 \
    && nok "-x without -k rejected" || ok "-x without -k rejected"

# 22. -x with --dm-table
if "$VERIFY" -t -d "$TEST_DIR/system.img" -k "$TEST_DIR/pubkey.bin" -x "$DIGEST" 2>/dev/null | grep -q "^0 .* verity "; then
    ok "-x with --dm-table"
else
    nok "-x with --dm-table"
fi

# 23. system_sig: dm-table includes root_hash_sig_key_desc
DM_SIG_OUT=$("$VERIFY" -t -d "$TEST_DIR/system_sig.img" -k "$TEST_DIR/pubkey.bin" 2>/dev/null)
echo "$DM_SIG_OUT" | grep -q "root_hash_sig_key_desc avb_roothash_sig.system" \
    && ok "dm-table has root_hash_sig_key_desc" || nok "dm-table has root_hash_sig_key_desc"

# 24. system_sig: verbose output shows Roothash sig field
SIG_OUT=$("$VERIFY" -d "$TEST_DIR/system_sig.img" -k "$TEST_DIR/pubkey.bin" 2>/dev/null)
echo "$SIG_OUT" | grep -q "Roothash sig:.*avb_roothash_sig.system" \
    && ok "verbose output has Roothash sig" || nok "verbose output has Roothash sig"

# 25. system_sig: key is in session keyring after extraction
# Run avb_verify explicitly here so this test does not depend on tests 23/24 having succeeded
"$VERIFY" -d "$TEST_DIR/system_sig.img" -k "$TEST_DIR/pubkey.bin" >/dev/null 2>/dev/null || true
if keyctl search @s user avb_roothash_sig.system >/dev/null 2>&1; then
    ok "roothash sig key in session keyring"
else
    nok "roothash sig key in session keyring"
fi

# 26. system without sig: dm-table does NOT have root_hash_sig_key_desc
DM_NOSIG=$("$VERIFY" -t -d "$TEST_DIR/system.img" -k "$TEST_DIR/pubkey.bin" 2>/dev/null)
if echo "$DM_NOSIG" | grep -q "root_hash_sig_key_desc"; then
    nok "dm-table without sig has no root_hash_sig_key_desc"
else
    ok "dm-table without sig has no root_hash_sig_key_desc"
fi

echo ""
echo "=== Results: $pass passed, $fail failed ==="
exit "$fail"
