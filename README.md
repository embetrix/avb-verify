# avb-verify

[![CI](https://github.com/embetrix/avb-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/embetrix/avb-verify/actions/workflows/ci.yml)

A C tool that brings [Android Verified Boot](https://android.googlesource.com/platform/external/avb/)
(AVB) to embedded Linux systems. It verifies AVB-signed images using `libavb`
and extracts dm-verity parameters ready for use with `dmsetup`, enabling
secure boot and runtime integrity verification on embedded hardware.

It implements two layers of verification:

1. **AVB layer**  validates the vbmeta PKCS#7 signature and checks the
   embedded public key against a trusted reference key (or its SHA-256
   digest, e.g. burned into OTP fuses).
2. **Root hash layer** *(optional)* if the vbmeta image contains a
   `roothash_sig` property (a PKCS#7 signature of the root hash), loads it
   into the kernel session keyring so dm-verity can independently verify the
   root hash via `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG`.

## Prerequisites

- CMake >= 3.10
- GCC or Clang
- [libavb](https://android.googlesource.com/platform/external/avb/) (submodule)
- Python 3 + OpenSSL  for signing images with `avbtool` (development only)

## Build

```bash
cmake -B build
cmake --build build
```

## Usage

```
avb_verify -d <device> -k <pubkey.bin> [-x <sha256>] [-t] [-h]
```

| Option | Description |
|---|---|
| `-d, --device <path>` | Image file or block device (required) |
| `-k, --pubkey <path>` | AVB public key in serialized format (required) |
| `-x, --pubkey-digest <hex>` | Also verify that the key's SHA-256 matches this digest |
| `-t, --dm-table` | Print only the raw dm-verity table line |
| `-h, --help` | Show help |

The public key must be in AVB's serialized format (not PEM). Extract it with:

```bash
python3 avb/avbtool.py extract_public_key --key key.pem --output pubkey.bin
```

### Default output

Prints a human-readable verification summary followed by the dm-verity table:

```bash
avb_verify -d /dev/mmcblk0p2 -k pubkey.bin
```

```
Verification:  OK
Algorithm:     SHA256_RSA4096
Rollback:      0
Partition:     system
Hash alg:      sha256
Data blocks:   16384
Data block sz: 4096
Hash block sz: 4096
Hash offset:   67108864
Root digest:   90e8fb28ff0657b17dfd92fe310dc00a94d7d97ddad8205efe5d37c5ff5ed3ba
Salt:          b2304b5cfecdf5862e626a779c78b0b09ffe35be0c5a02f972a9b5e7b9a6a2f1
Roothash sig:  avb_roothash_sig.system

dm table:
  0 131072 verity 1 /dev/mmcblk0p2 /dev/mmcblk0p2 4096 4096 16384 16384 \
  sha256 <root_digest> <salt> 1 root_hash_sig_key_desc avb_roothash_sig.system
```

`Roothash sig` and `root_hash_sig_key_desc` only appear when a `roothash_sig`
property is present in the vbmeta image (see [Root hash signature](#root-hash-signature)).

### dm-table mode

With `-t`, outputs only the raw dm-verity table line for direct use with
`dmsetup`:

```bash
avb_verify -t -d /dev/mmcblk0p2 -k pubkey.bin | dmsetup create verity-system
```

### Key digest verification

Use `-x` to additionally verify that the embedded public key matches a known
SHA-256 digest, typically a value burned into OTP fuses at manufacturing time
or retrieved from secure storage. This guards against TOCTOU attacks where a
compromised `pubkey.bin` is substituted between verification and use unlike
the key file, the OTP digest is immutable and cannot be altered at runtime:

```bash
avb_verify -d /dev/mmcblk0p2 -k pubkey.bin \
           -x $(sha256sum pubkey.bin | cut -d' ' -f1)
```

## How it works

1. **Locate the AVB footer**  checks the last 64 bytes first (standard
   location). If not found, detects the filesystem size from its superblock
   (ext4, erofs, squashfs) and scans forward in 1 MiB chunks from the
   filesystem boundary. This allows images signed with `--partition_size 0`
   to work correctly when written to a larger block device.
2. **Verify vbmeta signature**  calls `avb_vbmeta_image_verify()` from libavb.
3. **Check public key**  compares the key embedded in vbmeta against the
   trusted `pubkey.bin`, and optionally its SHA-256 digest.
4. **Extract dm-verity parameters**  parses the hashtree descriptor and
   builds the dm-verity table string.
5. **Load root hash signature** *(if present)*  reads the `roothash_sig`
   vbmeta property, loads the PKCS#7 blob into the session keyring via
   `add_key(2)`, and appends `root_hash_sig_key_desc` to the dm-verity table.

## Root hash signature

AVB's vbmeta signature is verified in userspace by `avb_verify` within the
initramfs (which is itself verified by the bootloader at an earlier boot stage).
However after Linux starts an attacker could tamper with `pubkey.bin` in
memory before `avb_verify` reads it causing it to accept a crafted vbmeta and
pass an attacker-controlled root hash to `dmsetup`.

The `roothash_sig` feature closes this window by delegating root hash
verification to the kernel: a PKCS#7 signature of the root hash is embedded
as a vbmeta property and loaded into the session keyring so dm-verity verifies
it atomically at device creation time, against the system's trusted keyring
(`CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG`).

### Signing workflow (build time)

Supported algorithms: `SHA256_RSA2048`, `SHA256_RSA4096`, `SHA256_RSA8192`,
`SHA512_RSA2048`, `SHA512_RSA4096`, `SHA512_RSA8192`, `MLDSA65`, `MLDSA87`.

```bash
# 1. Create the signing key and self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout sig_key.pem \
  -out sig_cert.pem -days 365 -nodes -subj "/CN=roothash-signer"

# 2. Sign the image with avbtool
python3 avb/avbtool.py add_hashtree_footer \
  --image system.img --partition_size 0 --partition_name system \
  --algorithm SHA256_RSA4096 --key key.pem --hash_algorithm sha256 \
  --do_not_generate_fec

# 3. Extract the root hash and salt, then create the PKCS#7 signature.
#    The salt must be reused in step 4 because avbtool generates a random salt
#    on each call, which would change the root hash and invalidate the signature.
#    The kernel passes the root hash as a hex string to verify_pkcs7_signature.
ROOT_HASH=$(python3 avb/avbtool.py info_image --image system.img \
  | sed -n 's/.*Root Digest:[[:space:]]*//p')
SALT=$(python3 avb/avbtool.py info_image --image system.img \
  | sed -n 's/.*Salt:[[:space:]]*//p')
echo -n "$ROOT_HASH" > roothash.hex

openssl smime -sign -nocerts -noattr -binary \
  -in roothash.hex -inkey sig_key.pem -signer sig_cert.pem \
  -outform der -out roothash.p7s

# 4. Re-sign the image with the same salt and the PKCS#7 blob embedded
python3 avb/avbtool.py erase_footer --image system.img
python3 avb/avbtool.py add_hashtree_footer \
  --image system.img --partition_size 0 --partition_name system \
  --algorithm SHA256_RSA4096 --key key.pem --hash_algorithm sha256 \
  --salt $SALT \
  --do_not_generate_fec \
  --prop_from_file roothash_sig:roothash.p7s
```

### Required kernel configuration

```
CONFIG_BLK_DEV_DM=y
CONFIG_DM_VERITY=y
CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y
CONFIG_KEYS=y
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS7_MESSAGE_PARSER=y
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_SYSTEM_TRUSTED_KEYS="/path/to/sig_cert.pem"
CONFIG_CRYPTO_RSA=y
CONFIG_CRYPTO_SHA256=y
```

#### ML-DSA support (Linux 7.x+)

```
CONFIG_CRYPTO_MLDSA=y
CONFIG_PKCS7_WAIVE_AUTHATTRS_REJECTION_FOR_MLDSA=y
```

#### Kernel Hardening
Add the option to your kernel cmdline to enforce root hash signature verification:

```
dm_verity.require_signatures=1
```

## Image layout

With `--partition_size 0`, `avbtool` appends metadata directly after the
filesystem data without padding to a fixed size:

```
Offset 0                      | filesystem data (ext4, squashfs, erofs, ...)
Offset <original_image_size>  | hashtree (dm-verity Merkle tree)
Offset <vbmeta_offset>        | VBMeta struct (signature + descriptors)
  ...padding to 4 KiB block...
End of last 4 KiB block − 64  | AVB footer (64 bytes)
```

When the image is written to a block device larger than the signed image,
trailing zeroes push the footer away from the device end. `avb_verify`
handles this by detecting the filesystem type from its superblock and
scanning forward from the filesystem boundary.

AVB footer fields:

| Field | Size | Description |
|---|---|---|
| Magic (`AVBf`) | 4 bytes | Identifies this as an AVB footer |
| Version major/minor | 8 bytes | Footer format version |
| `original_image_size` | 8 bytes | Filesystem size before signing |
| `vbmeta_offset` | 8 bytes | Byte offset of the VBMeta struct |
| `vbmeta_size` | 8 bytes | Size of the VBMeta struct |
| Reserved | 28 bytes | Padding |


## Tests

```bash
ctest --test-dir build -V
```

The test suite creates temporary ext4, erofs, and squashfs images, signs them,
and exercises all code paths: signature verification, key mismatch, corruption
detection, footer scanning on padded images, digest checking and root hash
signature loading.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
