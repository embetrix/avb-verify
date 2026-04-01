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

```bash
./avb_verify <image> <pubkey.bin> [device]
./avb_verify --dm-table <image> <pubkey.bin> [device]
```

The public key must be in AVB's serialized format (not PEM). Extract it with:

```bash
python3 avb/avbtool.py extract_public_key --key key.pem --output pubkey.bin
```

### Default mode

Verifies the image and prints all dm-verity parameters:

```bash
./avb_verify /dev/mmcblk0p2 pubkey.bin
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

dm table:
  0 131072 verity 1 /dev/mmcblk0p2 /dev/mmcblk0p2 4096 4096 16384 16384 sha256 ...
```

- `device` is optional overrides the image path in the dm table output

### --dm-table mode

Outputs only the raw dm-verity table line, suitable for piping to `dmsetup`:

```bash
./avb_verify --dm-table /dev/mmcblk0p2 pubkey.bin | dmsetup create verity-system
```

## How it works

1. Reads the **AVB footer** (last 64 bytes) to find the VBMeta offset
2. Calls `avb_vbmeta_image_verify()` from libavb to verify the signature
3. Compares the embedded public key against the trusted `pubkey.bin`
4. Extracts the hashtree descriptor and prints the **dm-verity table**

## Image layout

An AVB-signed partition has this layout:

```
Offset 0                      | filesystem data (ext4, squashfs, etc.)
Offset <original_image_size>  | hashtree (dm-verity Merkle tree)
Offset <vbmeta_offset>        | VBMeta struct (signature + descriptors)
  ...padding...
Offset <partition_size - 64>  | AVB footer (64 bytes)
```

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
  --partition_size 134217728 \
  --partition_name system \
  --algorithm SHA256_RSA4096 \
  --key key.pem \
  --hash_algorithm sha256 \
  --do_not_generate_fec
```

Supported algorithms: `SHA256_RSA2048`, `SHA256_RSA4096`, `SHA256_RSA8192`,
`SHA512_RSA2048`, `SHA512_RSA4096`, `SHA512_RSA8192`, `MLDSA65`, `MLDSA87`.

## Tests

```bash
ctest --test-dir build -V
```

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
