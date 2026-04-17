# AVB Image Verifier

[![CI](https://github.com/embetrix/avb-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/embetrix/avb-verify/actions/workflows/ci.yml)

A C tool that verifies [Android Verified Boot](https://android.googlesource.com/platform/external/avb/) (AVB) signed images
using `libavb` and extracts dm-verity parameters for use with `dmsetup`.

## Prerequisites

- CMake >= 3.10
- C compiler (GCC or Clang)
- Python 3 + OpenSSL (for signing images with `avbtool`)

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
| `-k, --pubkey <path>` | AVB public key file (required) |
| `-x, --pubkey-digest <hex>` | Verify key matches this SHA-256 digest (e.g. from OTP) |
| `-t, --dm-table` | Print only the raw dm table line |
| `-h, --help` | Show help |

The public key must be in AVB's serialized format (not PEM). Extract it with:

```bash
python3 avb/avbtool.py extract_public_key --key key.pem --output pubkey.bin
```

### Default mode

Verifies the image and prints all dm-verity parameters:

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
  0 131072 verity 1 /dev/mmcblk0p2 /dev/mmcblk0p2 4096 4096 16384 16384 sha256 ... 1 root_hash_sig_key_desc avb_roothash_sig.system
```

The `Roothash sig` field and the `root_hash_sig_key_desc` parameter only
appear when a `roothash_sig` property is found in the vbmeta image (see
[Root hash signature](#root-hash-signature) below).

### dm-table mode

With `-t`, outputs only the raw dm-verity table line, suitable for piping to `dmsetup`:

```bash
avb_verify -t -d /dev/mmcblk0p2 -k pubkey.bin | dmsetup create verity-system
```

### OTP key digest verification

Use `-x` to additionally verify that the public key's SHA-256 matches
a known digest (e.g. a value burned into OTP fuses):

```bash
avb_verify -d /dev/mmcblk0p2 -k pubkey.bin -x $(sha256sum pubkey.bin | cut -d' ' -f1)
```

## How it works

1. Scans for the **AVB footer**: first checks the last 64 bytes of the
   file/device, then detects the filesystem size from its superblock
   (ext4, erofs, squashfs) and scans forward in 1 MiB chunks starting
   just before the filesystem boundary.  Since `avbtool` always places
   the footer at the end of a 4 KiB-aligned block, this allows images
   signed with `--partition_size 0` to work even when written to a
   larger block device.
2. Calls `avb_vbmeta_image_verify()` from libavb to verify the signature
3. Compares the embedded public key against the trusted `pubkey.bin`
4. Extracts the hashtree descriptor and prints the **dm-verity table**
5. If a `roothash_sig` property is found, loads the PKCS#7 signature
   into the **session keyring** and appends `root_hash_sig_key_desc`
   to the dm-verity table

## Root hash signature

In addition to AVB's vbmeta signature (which protects the root hash at
the bootloader level), a separate PKCS#7 signature of the root hash can
be embedded as a vbmeta property. When present, `avb_verify` loads it
into the kernel session keyring via the `add_key()` syscall and appends
`root_hash_sig_key_desc` to the dm-verity table. This enables the kernel
to independently verify the root hash via
`CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG`.

### Signing the root hash (build time)

```bash
# 1. Sign the image normally
python3 avb/avbtool.py add_hashtree_footer \
  --image system.img --partition_size 0 --partition_name system \
  --algorithm SHA256_RSA4096 --key key.pem --hash_algorithm sha256 \
  --do_not_generate_fec

# 2. Extract the root hash
ROOT_HASH=$(python3 avb/avbtool.py info_image --image system.img \
  | sed -n 's/.*Root Digest:[[:space:]]*//p')
echo -n "$ROOT_HASH" | xxd -r -p > roothash.bin

# 3. Create a PKCS#7 signature of the root hash
openssl smime -sign -nocerts -noattr -binary \
  -in roothash.bin -inkey sig_key.pem -signer sig_cert.pem \
  -outform der -out roothash.p7s

# 4. Re-sign the image with the signature embedded as a property
python3 avb/avbtool.py erase_footer --image system.img
python3 avb/avbtool.py add_hashtree_footer \
  --image system.img --partition_size 0 --partition_name system \
  --algorithm SHA256_RSA4096 --key key.pem --hash_algorithm sha256 \
  --do_not_generate_fec \
  --prop_from_file roothash_sig:roothash.p7s
```

### Booting with root hash verification (target)

```bash
avb_verify -t -d /dev/mmcblk0p2 -k pubkey.bin | dmsetup create verity-system
```

`avb_verify` automatically:
1. Verifies the vbmeta signature (AVB layer)
2. Finds the `roothash_sig` property
3. Loads it into the session keyring as `avb_roothash_sig.<partition>`
4. Outputs the dm-verity table with `root_hash_sig_key_desc`
5. The kernel verifies the PKCS#7 signature against its trusted keyring

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

## Image layout

With `--partition_size 0`, `avbtool` appends metadata directly after the
filesystem data (no padding to a fixed partition size):

```
Offset 0                      | filesystem data (ext4, squashfs, etc.)
Offset <original_image_size>  | hashtree (dm-verity Merkle tree)
Offset <vbmeta_offset>        | VBMeta struct (signature + descriptors)
  ...padding to 4 KiB block...
End of last 4 KiB block − 64  | AVB footer (64 bytes)
```

When the image is written to a block device larger than the signed image,
trailing zeroes push the footer away from the end of the device.
`avb_verify` handles this by detecting the filesystem size from its
superblock and scanning forward in 1 MiB chunks from the filesystem
boundary.

The footer contains:

| Field                | Size     | Purpose                                    |
|----------------------|----------|--------------------------------------------|
| Magic (`AVBf`)       | 4 bytes  | Identifies this as an AVB footer           |
| Version major/minor  | 8 bytes  | Footer format version                      |
| `original_image_size`| 8 bytes  | Size of the filesystem data before signing |
| `vbmeta_offset`      | 8 bytes  | Byte offset of the VBMeta struct           |
| `vbmeta_size`        | 8 bytes  | Size of the VBMeta struct                  |
| Reserved             | 28 bytes | Padding                                    |

## Signing an image (for testing)

Generate a key and sign an ext4 image:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -outform PEM -out key.pem

dd if=/dev/zero of=system.img bs=1M count=64
mkfs.ext4 -F system.img

python3 avb/avbtool.py add_hashtree_footer \
  --image system.img \
  --partition_size 0 \
  --partition_name system \
  --algorithm SHA256_RSA4096 \
  --key key.pem \
  --hash_algorithm sha256 \
  --do_not_generate_fec
```

To include a root hash signature, add these steps after the initial signing:

```bash
# Generate a signing key/cert for the root hash
openssl req -x509 -newkey rsa:4096 -keyout sig_key.pem \
  -out sig_cert.pem -days 365 -nodes -subj "/CN=roothash-signer"

# Extract the root hash and sign it
ROOT_HASH=$(python3 avb/avbtool.py info_image --image system.img \
  | sed -n 's/.*Root Digest:[[:space:]]*//p')
echo -n "$ROOT_HASH" | xxd -r -p > roothash.bin

openssl smime -sign -nocerts -noattr -binary \
  -in roothash.bin -inkey sig_key.pem -signer sig_cert.pem \
  -outform der -out roothash.p7s

# Re-sign the image with the signature embedded as a vbmeta property
python3 avb/avbtool.py erase_footer --image system.img
python3 avb/avbtool.py add_hashtree_footer \
  --image system.img \
  --partition_size 0 \
  --partition_name system \
  --algorithm SHA256_RSA4096 \
  --key key.pem \
  --hash_algorithm sha256 \
  --do_not_generate_fec \
  --prop_from_file roothash_sig:roothash.p7s
```

Supported algorithms: `SHA256_RSA2048`, `SHA256_RSA4096`, `SHA256_RSA8192`,
`SHA512_RSA2048`, `SHA512_RSA4096`, `SHA512_RSA8192`, `MLDSA65`, `MLDSA87`.

## Tests

```bash
ctest --test-dir build -V
```

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
