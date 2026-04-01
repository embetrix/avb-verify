# AVB Verity — Signing an ext4 Image with avbtool

## Prerequisites

- Python 3
- OpenSSL
- `avbtool.py` (included in `avb/`)

## 1. Generate a Signing Key

Create an RSA 4096-bit private key:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -outform PEM -out test_key.pem
```

### Supported Algorithms

| Algorithm         | Key Type              |
|-------------------|-----------------------|
| `SHA256_RSA2048`  | RSA 2048-bit          |
| `SHA256_RSA4096`  | RSA 4096-bit          |
| `SHA256_RSA8192`  | RSA 8192-bit          |
| `SHA512_RSA2048`  | RSA 2048-bit          |
| `SHA512_RSA4096`  | RSA 4096-bit          |
| `SHA512_RSA8192`  | RSA 8192-bit          |
| `MLDSA65`         | ML-DSA (post-quantum) |
| `MLDSA87`         | ML-DSA (post-quantum) |

> **Note:** ECDSA is not supported by AVB.

## 2. Create a Dummy ext4 Image

Create a 64 MB ext4 filesystem image:

```bash
dd if=/dev/zero of=system.img bs=1M count=64
mkfs.ext4 -F system.img
```

## 3. Add a Hashtree Footer

For large filesystem images (ext4, erofs, squashfs), use `add_hashtree_footer`.
This appends a dm-verity Merkle tree, a VBMeta struct, and a footer to the image.

```bash
python3 avb/avbtool.py add_hashtree_footer \
  --image system.img \
  --partition_size 134217728 \
  --partition_name system \
  --algorithm SHA256_RSA4096 \
  --key test_key.pem \
  --hash_algorithm sha256 \
  --do_not_generate_fec
```

- `--partition_size` must be larger than the image to leave room for the hashtree and metadata. Here 128 MB is used for a 64 MB image.
- `--do_not_generate_fec` skips forward error correction (requires the `fec` tool from AOSP, not typically available on desktop Linux).
- `--hash_algorithm sha256` uses SHA-256 for the hashtree (default is sha1).

> For small images (boot, dtbo), use `add_hash_footer` instead — it stores a simple full-image hash rather than a Merkle tree.

## 4. Inspect the Image

```bash
python3 avb/avbtool.py info_image --image system.img
```

Example output:

```
Footer version:           1.0
Image size:               134217728 bytes
Original image size:      67108864 bytes
VBMeta offset:            67637248
VBMeta size:              2176 bytes
--
Algorithm:                SHA256_RSA4096
Rollback Index:           0
Descriptors:
    Hashtree descriptor:
      Version of dm-verity:  1
      Image Size:            67108864 bytes
      Tree Offset:           67108864
      Tree Size:             528384 bytes
      Hash Algorithm:        sha256
      Partition Name:        system
      Root Digest:           90e8fb28...
```

## 5. Verify the Image

```bash
python3 avb/avbtool.py verify_image --image system.img --key test_key.pem
```

This checks both the VBMeta signature and the hashtree integrity.

## Image Layout

After signing, the partition has this layout:

```
Offset 0                          → ext4 filesystem data (original image)
Offset <original_image_size>      → hashtree (dm-verity Merkle tree)
Offset <vbmeta_offset>            → VBMeta struct (signature + descriptors)
  ...padding...
Offset <partition_size - 64>      → AVB footer (64 bytes)
Offset <partition_size>           → end of partition
```

### AVB Footer (64 bytes, always at the last 64 bytes of the partition)

| Field                | Size     | Purpose                                    |
|----------------------|----------|--------------------------------------------|
| Magic (`AVBf`)       | 4 bytes  | Identifies this as an AVB footer           |
| Version major/minor  | 8 bytes  | Footer format version                      |
| `original_image_size`| 8 bytes  | Size of the filesystem data before signing |
| `vbmeta_offset`      | 8 bytes  | Byte offset of the VBMeta struct           |
| `vbmeta_size`        | 8 bytes  | Size of the VBMeta struct                  |
| Reserved             | 28 bytes | Padding                                    |

The bootloader locates the footer by seeking to `partition_size - 64`, then reads `vbmeta_offset` from it to find and verify the VBMeta struct.

## Other Useful Options

| Goal                                | Flag                                          |
|-------------------------------------|-----------------------------------------------|
| No signing (testing only)           | Omit `--algorithm` and `--key`                |
| Generate FEC data                   | Remove `--do_not_generate_fec` (needs `fec`)  |
| Set up as rootfs (dm-verity cmdline)| `--setup_as_rootfs_from_kernel`               |
| Extract VBMeta to a separate file   | `--output_vbmeta_image vbmeta_system.img`     |
| Remove the footer                   | `avbtool.py erase_footer --image system.img`  |
| Calculate max image size            | `--calc_max_image_size` (with `--partition_size`) |

## 6. Verify with the C Program (verify_avb)

A small C program (`verify_avb.c`) uses `libavb` to verify the VBMeta
signature, check the public key, and print dm-verity parameters.

### Build

```bash
make
```

### Extract the public key

The public key must be in AVB's serialized format (not PEM):

```bash
python3 avb/avbtool.py extract_public_key --key test_key.pem --output pubkey.bin
```

### Run

```bash
./verify_avb <image> <pubkey.bin> [device]
```

- `device` is optional — used in the dm table output (e.g. `/dev/mmcblk0p2`)

Example:

```bash
./verify_avb system.img pubkey.bin /dev/mmcblk0p2
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

### What it does

1. Reads the **AVB footer** (last 64 bytes) to find the VBMeta offset
2. Calls `avb_vbmeta_image_verify()` from libavb to verify the signature
3. Compares the embedded public key against the trusted `pubkey.bin`
4. Extracts hashtree parameters and prints the **dm-verity table**
