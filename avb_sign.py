#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# (C) Copyright 2026
# Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
"""
avb_sign.py - Append hash tree, sign and attach vbmeta with an embedded PKCS#7 root hash signature.

Automates the four-step signing workflow:
  1. First-pass avbtool add_hashtree_footer (generates random salt)
  2. Extract root hash and salt from the signed image
  3. Create a PKCS#7 signature over the root hash with openssl
  4. Re-sign with the pinned salt and roothash_sig property embedded

Usage:
    avb_sign.py --image IMAGE --key KEY --cert CERT [--output OUTPUT] [options]
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile


def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {' '.join(str(c) for c in cmd)}", file=sys.stderr)
        if result.stderr:
            print(result.stderr.rstrip(), file=sys.stderr)
        sys.exit(1)
    return result


def find_avbtool(hint):
    candidates = [hint] if hint else []
    candidates += [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "avb", "avbtool.py"),
        "avbtool",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    result = subprocess.run(["which", "avbtool"], capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    print("Error: avbtool not found. Use --avbtool to specify its path.", file=sys.stderr)
    sys.exit(1)


def avbtool_cmd(avbtool):
    if avbtool.endswith(".py"):
        return [sys.executable, avbtool]
    return [avbtool]


def main():
    parser = argparse.ArgumentParser(
        description="Sign an image with AVB and embed a PKCS#7 root hash signature."
    )
    parser.add_argument("--image", required=True,
                        help="Input image file")
    parser.add_argument("--output", default=None,
                        help="Output signed image (default: overwrite input)")
    parser.add_argument("--key", required=True,
                        help="Signing key in PEM format (used for both vbmeta and PKCS#7 roothash signature)")
    parser.add_argument("--cert", required=True,
                        help="Self-signed X.509 certificate (PEM) for PKCS#7 roothash signature")
    parser.add_argument("--partition-name", default="system",
                        help="Partition name embedded in vbmeta (default: system)")
    parser.add_argument("--algorithm", default="SHA256_RSA4096",
                        choices=[
                            "SHA256_RSA2048", "SHA256_RSA4096", "SHA256_RSA8192",
                            "SHA512_RSA2048", "SHA512_RSA4096", "SHA512_RSA8192",
                            "MLDSA65", "MLDSA87",
                        ],
                        help="AVB signing algorithm (default: SHA256_RSA4096)")
    parser.add_argument("--avbtool", default=None,
                        help="Path to avbtool or avbtool.py (auto-detected if omitted)")
    args = parser.parse_args()

    if not os.path.isfile(args.image):
        print(f"Error: image not found: {args.image}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(args.key):
        print(f"Error: key not found: {args.key}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(args.cert):
        print(f"Error: cert not found: {args.cert}", file=sys.stderr)
        sys.exit(1)

    avbtool = find_avbtool(args.avbtool)
    avb = avbtool_cmd(avbtool)

    work_image = args.output if args.output else args.image
    if args.output:
        shutil.copy2(args.image, args.output)

    print(f"Image:     {args.image}")
    if args.output:
        print(f"Output:    {args.output}")
    print(f"Key:       {args.key}")
    print(f"Cert:      {args.cert}")
    print(f"Partition: {args.partition_name}")
    print(f"Algorithm: {args.algorithm}")
    print()

    with tempfile.TemporaryDirectory() as tmpdir:
        roothash_file = os.path.join(tmpdir, "roothash.hex")
        p7s_file      = os.path.join(tmpdir, "roothash.p7s")

        # Step 1: first-pass signing with avbtool picks a random salt
        print("[1/4] Adding hashtree footer (first pass)...")
        run(avb + [
            "add_hashtree_footer",
            "--image",          work_image,
            "--partition_size", "0",
            "--partition_name", args.partition_name,
            "--algorithm",      args.algorithm,
            "--key",            args.key,
            "--hash_algorithm", "sha256",
            "--do_not_generate_fec",
        ])

        # Step 2: extract root hash and salt
        print("[2/4] Extracting root hash and salt...")
        info = run(avb + ["info_image", "--image", work_image])

        m_hash = re.search(r"Root Digest:\s*([0-9a-f]+)", info.stdout)
        m_salt = re.search(r"Salt:\s*([0-9a-f]+)", info.stdout)
        if not m_hash or not m_salt:
            print("Error: could not parse root hash or salt from avbtool info_image output:",
                  file=sys.stderr)
            print(info.stdout, file=sys.stderr)
            sys.exit(1)
        root_hash = m_hash.group(1)
        salt      = m_salt.group(1)
        print(f"  Root hash: {root_hash}")
        print(f"  Salt:      {salt}")

        # Step 3: PKCS#7 signature over root hash (hex string, no newline)
        print("[3/4] Creating PKCS#7 signature over root hash...")
        with open(roothash_file, "w") as f:
            f.write(root_hash)

        run([
            "openssl", "smime", "-sign",
            "-nocerts", "-noattr", "-binary",
            "-in",      roothash_file,
            "-inkey",   args.key,
            "-signer",  args.cert,
            "-outform", "der",
            "-out",     p7s_file,
        ])

        # Step 4: re-sign with pinned salt and roothash_sig embedded
        print("[4/4] Re-signing with pinned salt and embedded roothash_sig...")
        run(avb + ["erase_footer", "--image", work_image])
        run(avb + [
            "add_hashtree_footer",
            "--image",          work_image,
            "--partition_size", "0",
            "--partition_name", args.partition_name,
            "--algorithm",      args.algorithm,
            "--key",            args.key,
            "--hash_algorithm", "sha256",
            "--salt",           salt,
            "--do_not_generate_fec",
            "--prop_from_file", f"roothash_sig:{p7s_file}",
        ])

    print()
    print("Done.")


if __name__ == "__main__":
    main()
