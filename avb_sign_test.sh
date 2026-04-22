#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# (C) Copyright 2026
# Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
#
# Integration tests for avb_sign.py
set -euo pipefail

AVBTOOL="python3 avb/avbtool.py"
SIGN="python3 avb_sign.py"
VERIFY="${avb_verify:-./build/avb_verify}"
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

for tool in openssl mkfs.ext4; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool '$tool' not found" >&2
        exit 1
    fi
done

pass=0
fail=0

ok()  { echo "  PASS  $1"; pass=$((pass + 1)); }
nok() { echo "  FAIL  $1"; fail=$((fail + 1)); }

echo "=== Setting up test fixtures ==="

# Signing key + self-signed cert (same key for both AVB and PKCS#7)
openssl genrsa -out "$TEST_DIR/key.pem" 4096 2>/dev/null
openssl req -x509 -key "$TEST_DIR/key.pem" -out "$TEST_DIR/sig_cert.pem" \
    -days 365 -subj "/CN=avb-signer" 2>/dev/null

# Wrong key + cert (mismatched against key.pem)
openssl genrsa -out "$TEST_DIR/wrong_key.pem" 4096 2>/dev/null
openssl req -x509 -key "$TEST_DIR/wrong_key.pem" -out "$TEST_DIR/wrong_cert.pem" \
    -days 365 -subj "/CN=wrong-signer" 2>/dev/null

# Unsigned ext4 image (4 MB)
truncate -s 4M "$TEST_DIR/rootfs.ext4"
mkfs.ext4 -q "$TEST_DIR/rootfs.ext4"

# AVB public key for avb_verify
$AVBTOOL extract_public_key --key "$TEST_DIR/key.pem" --output "$TEST_DIR/pubkey.bin"

echo ""
echo "=== Running tests ==="

# 1. Basic signing in-place succeeds
cp "$TEST_DIR/rootfs.ext4" "$TEST_DIR/inplace.ext4"
if $SIGN --image "$TEST_DIR/inplace.ext4" \
         --key "$TEST_DIR/key.pem" \
         --cert "$TEST_DIR/sig_cert.pem" \
         --partition-name rootfs >/dev/null 2>&1; then
    ok "basic signing in-place"
else
    nok "basic signing in-place"
fi

# 2. avb_verify accepts the in-place signed image
if "$VERIFY" -d "$TEST_DIR/inplace.ext4" -k "$TEST_DIR/pubkey.bin" \
        2>/dev/null | grep -q "Verification:  OK"; then
    ok "avb_verify accepts signed image"
else
    nok "avb_verify accepts signed image"
fi

# 3. roothash_sig property is embedded in the signed image
if $AVBTOOL info_image --image "$TEST_DIR/inplace.ext4" 2>/dev/null \
        | grep -q "roothash_sig"; then
    ok "roothash_sig property embedded"
else
    nok "roothash_sig property embedded"
fi

# 4. dm-verity table includes root_hash_sig_key_desc
if "$VERIFY" -t -d "$TEST_DIR/inplace.ext4" -k "$TEST_DIR/pubkey.bin" \
        2>/dev/null | grep -q "root_hash_sig_key_desc"; then
    ok "dm-table has root_hash_sig_key_desc"
else
    nok "dm-table has root_hash_sig_key_desc"
fi

# 5. --output leaves input image unchanged
BEFORE=$(md5sum "$TEST_DIR/rootfs.ext4" | cut -d' ' -f1)
$SIGN --image "$TEST_DIR/rootfs.ext4" \
      --output "$TEST_DIR/rootfs-signed.ext4" \
      --key "$TEST_DIR/key.pem" \
      --cert "$TEST_DIR/sig_cert.pem" \
      --partition-name rootfs >/dev/null 2>&1
AFTER=$(md5sum "$TEST_DIR/rootfs.ext4" | cut -d' ' -f1)
[[ "$BEFORE" == "$AFTER" ]] && ok "--output leaves input unchanged" \
                              || nok "--output leaves input unchanged"

# 6. avb_verify accepts the --output signed image
if "$VERIFY" -d "$TEST_DIR/rootfs-signed.ext4" -k "$TEST_DIR/pubkey.bin" \
        2>/dev/null | grep -q "Verification:  OK"; then
    ok "--output image verifies"
else
    nok "--output image verifies"
fi

# 7. --output embeds roothash_sig
if $AVBTOOL info_image --image "$TEST_DIR/rootfs-signed.ext4" 2>/dev/null \
        | grep -q "roothash_sig"; then
    ok "--output image has roothash_sig"
else
    nok "--output image has roothash_sig"
fi

# 8. Custom --partition-name is reflected in dm-verity table
cp "$TEST_DIR/rootfs.ext4" "$TEST_DIR/custom_part.ext4"
$SIGN --image "$TEST_DIR/custom_part.ext4" \
      --key "$TEST_DIR/key.pem" \
      --cert "$TEST_DIR/sig_cert.pem" \
      --partition-name mypart >/dev/null 2>&1
if "$VERIFY" -d "$TEST_DIR/custom_part.ext4" -k "$TEST_DIR/pubkey.bin" \
        2>/dev/null | grep -q "Partition:.*mypart"; then
    ok "custom --partition-name"
else
    nok "custom --partition-name"
fi

# 9. Custom --algorithm is used (SHA512_RSA4096 matches the 4096-bit test key)
cp "$TEST_DIR/rootfs.ext4" "$TEST_DIR/algo.ext4"
if $SIGN --image "$TEST_DIR/algo.ext4" \
         --key "$TEST_DIR/key.pem" \
         --cert "$TEST_DIR/sig_cert.pem" \
         --algorithm SHA512_RSA4096 >/dev/null 2>&1; then
    ok "custom --algorithm accepted"
else
    nok "custom --algorithm accepted"
fi

# 10. cert not matching key is rejected
cp "$TEST_DIR/rootfs.ext4" "$TEST_DIR/mismatch.ext4"
$SIGN --image "$TEST_DIR/mismatch.ext4" \
      --key "$TEST_DIR/key.pem" \
      --cert "$TEST_DIR/wrong_cert.pem" >/dev/null 2>&1 \
    && nok "cert/key mismatch rejected" || ok "cert/key mismatch rejected"

# 11. missing --image fails
$SIGN --key "$TEST_DIR/key.pem" --cert "$TEST_DIR/sig_cert.pem" >/dev/null 2>&1 \
    && nok "missing --image fails" || ok "missing --image fails"

# 12. missing --key fails
$SIGN --image "$TEST_DIR/rootfs.ext4" --cert "$TEST_DIR/sig_cert.pem" >/dev/null 2>&1 \
    && nok "missing --key fails" || ok "missing --key fails"

# 13. missing --cert fails
$SIGN --image "$TEST_DIR/rootfs.ext4" --key "$TEST_DIR/key.pem" >/dev/null 2>&1 \
    && nok "missing --cert fails" || ok "missing --cert fails"

# 14. nonexistent image fails
$SIGN --image "$TEST_DIR/no_such.ext4" \
      --key "$TEST_DIR/key.pem" \
      --cert "$TEST_DIR/sig_cert.pem" >/dev/null 2>&1 \
    && nok "nonexistent image fails" || ok "nonexistent image fails"

# 15. nonexistent key fails
$SIGN --image "$TEST_DIR/rootfs.ext4" \
      --key "$TEST_DIR/no_key.pem" \
      --cert "$TEST_DIR/sig_cert.pem" >/dev/null 2>&1 \
    && nok "nonexistent key fails" || ok "nonexistent key fails"

# 16. nonexistent cert fails
$SIGN --image "$TEST_DIR/rootfs.ext4" \
      --key "$TEST_DIR/key.pem" \
      --cert "$TEST_DIR/no_cert.pem" >/dev/null 2>&1 \
    && nok "nonexistent cert fails" || ok "nonexistent cert fails"

echo ""
echo "=== Results: $pass passed, $fail failed ==="
exit "$fail"
