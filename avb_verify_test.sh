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

# Create a small ext4 image (4MB filesystem)
truncate -s 4M "$TMPDIR/system.img"
mkfs.ext4 -q "$TMPDIR/system.img"

# Sign with add_hashtree_footer (--partition_size 0 appends footer at end of data)
$AVBTOOL add_hashtree_footer \
    --image "$TMPDIR/system.img" \
    --partition_name system \
    --partition_size 0 \
    --algorithm SHA256_RSA4096 \
    --hash_algorithm sha256 \
    --key "$TMPDIR/key.pem" \
    --do_not_generate_fec

# Extract the root hash from the signed image, create PKCS#7 signature,
# and rebuild with the signature embedded as a property.
ROOT_HASH=$($AVBTOOL info_image --image "$TMPDIR/system.img" 2>/dev/null \
    | sed -n 's/.*Root Digest:[[:space:]]*//p')
echo -n "$ROOT_HASH" | xxd -r -p > "$TMPDIR/roothash.bin"

# Create a self-signed certificate for root hash signing
openssl req -x509 -newkey rsa:4096 -keyout "$TMPDIR/sig_key.pem" \
    -out "$TMPDIR/sig_cert.pem" -days 365 -nodes \
    -subj "/CN=roothash-signer" 2>/dev/null

# Create PKCS#7 detached signature of the root hash
openssl smime -sign -nocerts -noattr -binary \
    -in "$TMPDIR/roothash.bin" -inkey "$TMPDIR/sig_key.pem" \
    -signer "$TMPDIR/sig_cert.pem" \
    -outform der -out "$TMPDIR/roothash.p7s"

# Create a second image with the signature embedded as a property
cp "$TMPDIR/system.img" "$TMPDIR/system_sig.img"
# Strip existing footer, re-sign with --prop_from_file
$AVBTOOL erase_footer --image "$TMPDIR/system_sig.img" 2>/dev/null
$AVBTOOL add_hashtree_footer \
    --image "$TMPDIR/system_sig.img" \
    --partition_name system \
    --partition_size 0 \
    --algorithm SHA256_RSA4096 \
    --hash_algorithm sha256 \
    --key "$TMPDIR/key.pem" \
    --do_not_generate_fec \
    --prop_from_file roothash_sig:"$TMPDIR/roothash.p7s"

# Create a small erofs image
mkdir -p "$TMPDIR/erofs_root"
echo "erofs test" > "$TMPDIR/erofs_root/hello.txt"
mkfs.erofs "$TMPDIR/erofs.img" "$TMPDIR/erofs_root" 2>/dev/null

$AVBTOOL add_hashtree_footer \
    --image "$TMPDIR/erofs.img" \
    --partition_name erofs_part \
    --partition_size 0 \
    --algorithm SHA256_RSA4096 \
    --hash_algorithm sha256 \
    --key "$TMPDIR/key.pem" \
    --do_not_generate_fec

# Create a small squashfs image
mkdir -p "$TMPDIR/squashfs_root"
echo "squashfs test" > "$TMPDIR/squashfs_root/hello.txt"
mksquashfs "$TMPDIR/squashfs_root" "$TMPDIR/squashfs.img" -quiet -noappend

$AVBTOOL add_hashtree_footer \
    --image "$TMPDIR/squashfs.img" \
    --partition_name squashfs_part \
    --partition_size 0 \
    --algorithm SHA256_RSA4096 \
    --hash_algorithm sha256 \
    --key "$TMPDIR/key.pem" \
    --do_not_generate_fec

echo ""
echo "=== Running tests ==="

# 1. Basic verification succeeds
if OUT=$("$VERIFY" -d "$TMPDIR/system.img" -k "$TMPDIR/pubkey.bin" 2>&1); then
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
DM_OUT=$("$VERIFY" -t -d "$TMPDIR/system.img" -k "$TMPDIR/pubkey.bin")
DM_LINES=$(echo "$DM_OUT" | wc -l)
[[ $DM_LINES -eq 1 ]] && ok "--dm-table outputs single line" || nok "--dm-table outputs single line"
echo "$DM_OUT" | grep -q "^0 .* verity " && ok "--dm-table starts with 0" || nok "--dm-table starts with 0"

# 4. Wrong key is rejected
"$VERIFY" -d "$TMPDIR/system.img" -k "$TMPDIR/wrong_pubkey.bin" >/dev/null 2>&1 \
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
"$VERIFY" -d "$TMPDIR/corrupt.img" -k "$TMPDIR/pubkey.bin" >/dev/null 2>&1 \
    && nok "corrupted image rejected" || ok "corrupted image rejected"

# 7. Truncated file is rejected
truncate -s 32 "$TMPDIR/tiny.img"
"$VERIFY" -d "$TMPDIR/tiny.img" -k "$TMPDIR/pubkey.bin" >/dev/null 2>&1 \
    && nok "truncated file rejected" || ok "truncated file rejected"

# 8. Footer scanning: image padded to a larger size (simulates writing to a bigger device)
cp "$TMPDIR/system.img" "$TMPDIR/padded.img"
truncate -s 8M "$TMPDIR/padded.img"
if "$VERIFY" -d "$TMPDIR/padded.img" -k "$TMPDIR/pubkey.bin" >/dev/null 2>&1; then
    ok "footer scanning on padded image"
else
    nok "footer scanning on padded image"
fi

# 9. Footer scanning produces no spurious errors on stderr
SCAN_ERR=$("$VERIFY" -d "$TMPDIR/padded.img" -k "$TMPDIR/pubkey.bin" 2>&1 >/dev/null)
if echo "$SCAN_ERR" | grep -q "ERROR"; then
    nok "footer scan has no ERROR on stderr"
else
    ok "footer scan has no ERROR on stderr"
fi

# 11. Missing arguments shows usage
USAGE_OUT=$("$VERIFY" 2>&1 || true)
echo "$USAGE_OUT" | grep -q "Usage" \
    && ok "no args shows usage" || nok "no args shows usage"

# 12. Nonexistent image file
"$VERIFY" -d "$TMPDIR/nonexistent.img" -k "$TMPDIR/pubkey.bin" >/dev/null 2>&1 \
    && nok "nonexistent image rejected" || ok "nonexistent image rejected"

# 13. Nonexistent key file
"$VERIFY" -d "$TMPDIR/system.img" -k "$TMPDIR/nonexistent.bin" >/dev/null 2>&1 \
    && nok "nonexistent key rejected" || ok "nonexistent key rejected"

# 14. erofs: basic verification
if "$VERIFY" -d "$TMPDIR/erofs.img" -k "$TMPDIR/pubkey.bin" 2>/dev/null | grep -q "Verification:  OK"; then
    ok "erofs basic verification"
else
    nok "erofs basic verification"
fi

# 15. erofs: --dm-table output
if "$VERIFY" -t -d "$TMPDIR/erofs.img" -k "$TMPDIR/pubkey.bin" 2>/dev/null | grep -q "^0 .* verity "; then
    ok "erofs --dm-table output"
else
    nok "erofs --dm-table output"
fi

# 16. erofs: footer scanning on padded image
cp "$TMPDIR/erofs.img" "$TMPDIR/erofs_padded.img"
truncate -s 8M "$TMPDIR/erofs_padded.img"
if "$VERIFY" -d "$TMPDIR/erofs_padded.img" -k "$TMPDIR/pubkey.bin" >/dev/null 2>&1; then
    ok "erofs footer scanning on padded image"
else
    nok "erofs footer scanning on padded image"
fi

# 17. squashfs: basic verification
if "$VERIFY" -d "$TMPDIR/squashfs.img" -k "$TMPDIR/pubkey.bin" 2>/dev/null | grep -q "Verification:  OK"; then
    ok "squashfs basic verification"
else
    nok "squashfs basic verification"
fi

# 18. squashfs: --dm-table output
if "$VERIFY" -t -d "$TMPDIR/squashfs.img" -k "$TMPDIR/pubkey.bin" 2>/dev/null | grep -q "^0 .* verity "; then
    ok "squashfs --dm-table output"
else
    nok "squashfs --dm-table output"
fi

# 19. squashfs: footer scanning on padded image
cp "$TMPDIR/squashfs.img" "$TMPDIR/squashfs_padded.img"
truncate -s 8M "$TMPDIR/squashfs_padded.img"
if "$VERIFY" -d "$TMPDIR/squashfs_padded.img" -k "$TMPDIR/pubkey.bin" >/dev/null 2>&1; then
    ok "squashfs footer scanning on padded image"
else
    nok "squashfs footer scanning on padded image"
fi

# 20. -x: verification succeeds with correct digest
DIGEST=$(sha256sum "$TMPDIR/pubkey.bin" | cut -d' ' -f1)
if "$VERIFY" -d "$TMPDIR/system.img" -k "$TMPDIR/pubkey.bin" -x "$DIGEST" 2>/dev/null | grep -q "Verification:  OK"; then
    ok "-x correct digest"
else
    nok "-x correct digest"
fi

# 21. -x: wrong digest is rejected
WRONG_DIGEST=$(sha256sum "$TMPDIR/wrong_pubkey.bin" | cut -d' ' -f1)
"$VERIFY" -d "$TMPDIR/system.img" -k "$TMPDIR/pubkey.bin" -x "$WRONG_DIGEST" >/dev/null 2>&1 \
    && nok "-x wrong digest rejected" || ok "-x wrong digest rejected"

# 22. -x: invalid hex is rejected
"$VERIFY" -d "$TMPDIR/system.img" -k "$TMPDIR/pubkey.bin" -x "not_hex" >/dev/null 2>&1 \
    && nok "-x invalid hex rejected" || ok "-x invalid hex rejected"

# 23. -x without -k is rejected
"$VERIFY" -d "$TMPDIR/system.img" -x "$DIGEST" >/dev/null 2>&1 \
    && nok "-x without -k rejected" || ok "-x without -k rejected"

# 24. -x with --dm-table
if "$VERIFY" -t -d "$TMPDIR/system.img" -k "$TMPDIR/pubkey.bin" -x "$DIGEST" 2>/dev/null | grep -q "^0 .* verity "; then
    ok "-x with --dm-table"
else
    nok "-x with --dm-table"
fi

# 25. system_sig: dm-table includes root_hash_sig_key_desc
DM_SIG_OUT=$("$VERIFY" -t -d "$TMPDIR/system_sig.img" -k "$TMPDIR/pubkey.bin" 2>/dev/null)
echo "$DM_SIG_OUT" | grep -q "root_hash_sig_key_desc avb_roothash_sig.system" \
    && ok "dm-table has root_hash_sig_key_desc" || nok "dm-table has root_hash_sig_key_desc"

# 26. system_sig: verbose output shows Roothash sig field
SIG_OUT=$("$VERIFY" -d "$TMPDIR/system_sig.img" -k "$TMPDIR/pubkey.bin" 2>/dev/null)
echo "$SIG_OUT" | grep -q "Roothash sig:.*avb_roothash_sig.system" \
    && ok "verbose output has Roothash sig" || nok "verbose output has Roothash sig"

# 27. system_sig: key is in session keyring after extraction
if keyctl search @s user avb_roothash_sig.system >/dev/null 2>&1; then
    ok "roothash sig key in session keyring"
else
    nok "roothash sig key in session keyring"
fi

# 28. system without sig: dm-table does NOT have root_hash_sig_key_desc
DM_NOSIG=$("$VERIFY" -t -d "$TMPDIR/system.img" -k "$TMPDIR/pubkey.bin" 2>/dev/null)
if echo "$DM_NOSIG" | grep -q "root_hash_sig_key_desc"; then
    nok "dm-table without sig has no root_hash_sig_key_desc"
else
    ok "dm-table without sig has no root_hash_sig_key_desc"
fi

echo ""
echo "=== Results: $pass passed, $fail failed ==="
exit "$fail"
