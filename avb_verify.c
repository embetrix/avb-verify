// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * (C) Copyright 2026
 * Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
 *
 * avb_verify.c : AVB image verifier + dm-verity parameter extractor
 *
 * Verifies the VBMeta signature, checks the public key, and prints
 * the dm-verity table.
 *
 * Extract the public key with:
 *   avbtool extract_public_key --key key.pem --output pubkey.bin
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <libavb/libavb.h>

#define FAIL(...) do { fprintf(stderr, __VA_ARGS__); ret = 1; goto out; } while (0)

/* avbtool block size footer is aligned at the end of a 4 KiB block */
#define AVB_BLOCK_SIZE  4096

/* Scan chunk size: 1 MiB */
#define SCAN_CHUNK_SIZE  (1024 * 1024)

/* Maximum number of blocks to scan backwards when searching for the
 * AVB footer.  Covers block devices up to 2048 MiB larger than the
 * actual signed image.  Increase if needed. */
#define FOOTER_SCAN_MAX_BLOCKS  ((2048ULL * 1024 * 1024) / AVB_BLOCK_SIZE)

/* Hashtree params */
typedef struct {
  bool found;
  AvbHashtreeDescriptor ht;
  const uint8_t *partition_name;
  const uint8_t *salt;
  const uint8_t *root_digest;
} HashtreeInfo;

/* Little-endian field readers (ext4/erofs superblocks are LE) */
static uint16_t read_le16(const uint8_t *p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_le64(const uint8_t *p) {
  return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

/* Detect filesystem size from superblock (ext4, erofs sor squashfs).
 * Returns the filesystem size in bytes or 0 if unknown. */
static uint64_t detect_fs_size(FILE *fp) {
  uint8_t sb[4096];
  fseek(fp, 0, SEEK_SET);
  if (fread(sb, 1, sizeof(sb), fp) < 2048)
    return 0;

  /* ext4: superblock at offset 1024, magic 0xEF53 at sb+56 */
  if (read_le16(sb + 1024 + 56) == 0xEF53) {
    uint32_t s_blocks_count_lo = read_le32(sb + 1024 + 4);
    uint32_t s_log_block_size  = read_le32(sb + 1024 + 24);
    uint64_t block_size = 1024ULL << s_log_block_size;
    return (uint64_t)s_blocks_count_lo * block_size;
  }

  /* erofs: superblock at offset 1024, magic 0xE0F5E1E2 at sb+0 */
  if (read_le32(sb + 1024) == 0xE0F5E1E2) {
    uint8_t blkszbits = sb[1024 + 12];
    uint32_t blocks = read_le32(sb + 1024 + 36);
    return (uint64_t)blocks << blkszbits;
  }

  /* squashfs: magic "hsqs" (0x73717368) at offset 0, bytes_used at offset 40 */
  if (read_le32(sb) == 0x73717368) {
    return read_le64(sb + 40);
  }

  return 0;
}

static void print_hex(const uint8_t *data, size_t len) {

  for (size_t i = 0; i < len; i++)
    printf("%02x", data[i]);
}

static uint8_t *read_file_all(const char *path, size_t *out_size) {

  FILE *fp = fopen(path, "rb");
  if (!fp) {
    fprintf(stderr, "Error: cannot open '%s': %s\n", path, strerror(errno));
    return NULL;
  }
  fseek(fp, 0, SEEK_END);
  long len = ftell(fp);
  if (len < 0) { fclose(fp); return NULL; }
  rewind(fp);
  uint8_t *buf = malloc((size_t)len);
  if (!buf) { fclose(fp); return NULL; }
  if (fread(buf, 1, (size_t)len, fp) != (size_t)len) {
    free(buf); fclose(fp); return NULL;
  }
  fclose(fp);
  *out_size = (size_t)len;
  return buf;
}

static const char *algorithm_name(uint32_t type) {

  switch (type) {
    case AVB_ALGORITHM_TYPE_SHA256_RSA2048: return "SHA256_RSA2048";
    case AVB_ALGORITHM_TYPE_SHA256_RSA4096: return "SHA256_RSA4096";
    case AVB_ALGORITHM_TYPE_SHA256_RSA8192: return "SHA256_RSA8192";
    case AVB_ALGORITHM_TYPE_SHA512_RSA2048: return "SHA512_RSA2048";
    case AVB_ALGORITHM_TYPE_SHA512_RSA4096: return "SHA512_RSA4096";
    case AVB_ALGORITHM_TYPE_SHA512_RSA8192: return "SHA512_RSA8192";
    case AVB_ALGORITHM_TYPE_MLDSA65:       return "MLDSA65";
    case AVB_ALGORITHM_TYPE_MLDSA87:       return "MLDSA87";
    default: return "NONE";
  }
}

/* Descriptor callback — find the first hashtree descriptor. */
static bool find_hashtree(const AvbDescriptor *desc, void *user_data) {

  HashtreeInfo *info = (HashtreeInfo *)user_data;
  AvbDescriptor header;
  if (!avb_descriptor_validate_and_byteswap(desc, &header))
    return true;
  if (header.tag != AVB_DESCRIPTOR_TAG_HASHTREE)
    return true;
  if (!avb_hashtree_descriptor_validate_and_byteswap(
          (const AvbHashtreeDescriptor *)desc, &info->ht))
    return true;
  const uint8_t *p = (const uint8_t *)desc + sizeof(AvbHashtreeDescriptor);
  info->partition_name = p;
  info->salt = p + info->ht.partition_name_len;
  info->root_digest = info->salt + info->ht.salt_len;
  info->found = true;
  return false;
}

static void usage(const char *prog) {
  fprintf(stderr,
    "Usage: %s -i <image> -k <pubkey.bin> [-d <device>] [-t] [-h]\n\n"
    "Verify AVB signature and print dm-verity parameters.\n\n"
    "Options:\n"
    "  -i, --image <path>    Image file or block device (required)\n"
    "  -k, --key <path>      AVB public key file (required)\n"
    "  -d, --device <path>   Device path for dm table (default: image path)\n"
    "  -t, --dm-table        Print only the raw dm table line\n"
    "  -h, --help            Show this help\n\n"
    "Examples:\n"
    "  %s -i /dev/mmcblk0p2 -k pubkey.bin\n"
    "  %s -t -i /dev/mmcblk0p2 -k pubkey.bin | dmsetup create verity-system\n",
    prog, prog, prog);
}

int main(int argc, char *argv[]) {

  bool dm_table_only = false;
  const char *image_path  = NULL;
  const char *pubkey_path = NULL;
  const char *device_path = NULL;

  int ret = 0;
  uint8_t *trusted_key = NULL;
  uint8_t *vbmeta = NULL;
  FILE *fp = NULL;

  static const struct option long_opts[] = {
    {"image",    required_argument, NULL, 'i'},
    {"key",      required_argument, NULL, 'k'},
    {"device",   required_argument, NULL, 'd'},
    {"dm-table", no_argument,       NULL, 't'},
    {"help",     no_argument,       NULL, 'h'},
    {NULL, 0, NULL, 0}
  };

  int opt;
  while ((opt = getopt_long(argc, argv, "i:k:d:th", long_opts, NULL)) != -1) {
    switch (opt) {
      case 'i': image_path  = optarg; break;
      case 'k': pubkey_path = optarg; break;
      case 'd': device_path = optarg; break;
      case 't': dm_table_only = true; break;
      case 'h':
      default:
        usage(argv[0]);
        return (opt == 'h') ? 0 : 1;
    }
  }

  if (!image_path || !pubkey_path) {
    usage(argv[0]);
    return 1;
  }

  if (!device_path)
    device_path = image_path;

  /* Load trusted public key */
  size_t trusted_key_size;
  trusted_key = read_file_all(pubkey_path, &trusted_key_size);
  if (!trusted_key) return 1;

  /* Open image and find AVB footer
   * Try the last 64 bytes first (standard location).  If not found,
   * scan backwards looking for the "AVBf" magic so that images created
   * with --partition_size 0 work on larger block devices */
  fp = fopen(image_path, "rb");
  if (!fp)
    FAIL("Error: cannot open '%s': %s\n", image_path, strerror(errno));

  fseek(fp, 0, SEEK_END);
  uint64_t image_size = (uint64_t)ftell(fp);
  if (image_size < AVB_FOOTER_SIZE)
    FAIL("Error: image too small for AVB footer.\n");

  AvbFooter raw_footer, footer;
  bool footer_found = false;
  struct timespec ts_start, ts_end;

  clock_gettime(CLOCK_MONOTONIC, &ts_start);

  /* Fast path: footer at end of file/device */
  fseek(fp, (long)(image_size - AVB_FOOTER_SIZE), SEEK_SET);
  if (fread(&raw_footer, 1, AVB_FOOTER_SIZE, fp) == AVB_FOOTER_SIZE &&
      memcmp(raw_footer.magic, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) == 0 &&
      avb_footer_validate_and_byteswap(&raw_footer, &footer))
    footer_found = true;

  /* Slow path: scan forward in 1 MiB chunks.
   * Try to detect the filesystem size from its superblock so that we
   * can skip the bulk of the filesystem data and start scanning right
   * before the AVB metadata (hashtree + vbmeta + footer) */
  if (!footer_found) {
    uint8_t *chunk = malloc(SCAN_CHUNK_SIZE);
    if (!chunk)
      FAIL("Error: out of memory.\n");

    uint64_t scan_end = image_size;
    uint64_t max_scan = FOOTER_SCAN_MAX_BLOCKS * (uint64_t)AVB_BLOCK_SIZE;
    if (scan_end > max_scan)
      scan_end = max_scan;

    /* Start scanning from just before the detected filesystem end,
     * or from offset 0 if detection fails. */
    uint64_t fs_size = detect_fs_size(fp);
    uint64_t scan_start = 0;
    if (fs_size > SCAN_CHUNK_SIZE)
      scan_start = (fs_size - SCAN_CHUNK_SIZE) & ~(uint64_t)(AVB_BLOCK_SIZE - 1);

    for (uint64_t pos = scan_start; pos < scan_end && !footer_found; ) {
      uint64_t chunk_len = scan_end - pos;
      if (chunk_len > SCAN_CHUNK_SIZE)
        chunk_len = SCAN_CHUNK_SIZE;

      fseek(fp, (long)pos, SEEK_SET);
      size_t got = fread(chunk, 1, (size_t)chunk_len, fp);
      if (got < AVB_BLOCK_SIZE)
        break;

      /* Check each 4 KiB footer position within this chunk */
      uint64_t last_off = (got / AVB_BLOCK_SIZE) * AVB_BLOCK_SIZE - AVB_FOOTER_SIZE;
      for (uint64_t off = AVB_BLOCK_SIZE - AVB_FOOTER_SIZE; off <= last_off; off += AVB_BLOCK_SIZE) {
        if (memcmp(chunk + off, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) != 0)
          continue;
        memcpy(&raw_footer, chunk + off, AVB_FOOTER_SIZE);
        if (avb_footer_validate_and_byteswap(&raw_footer, &footer)) {
          footer_found = true;
          break;
        }
      }
      pos += got;
    }
    free(chunk);
  }

  clock_gettime(CLOCK_MONOTONIC, &ts_end);
  double scan_ms = (ts_end.tv_sec - ts_start.tv_sec) * 1000.0 +
                   (ts_end.tv_nsec - ts_start.tv_nsec) / 1e6;
  fprintf(stderr, "Footer scan: %.3f ms\n", scan_ms);

  if (!footer_found)
    FAIL("Error: AVB footer not found.\n");

  /* Read VBMeta blob */
  vbmeta = malloc((size_t)footer.vbmeta_size);
  if (!vbmeta)
    FAIL("Error: out of memory.\n");
  fseek(fp, (long)footer.vbmeta_offset, SEEK_SET);
  if (fread(vbmeta, 1, (size_t)footer.vbmeta_size, fp) != footer.vbmeta_size)
    FAIL("Error: could not read VBMeta.\n");
  fclose(fp); fp = NULL;

  /* Verify VBMeta signature */
  const uint8_t *embedded_key;
  size_t embedded_key_size;
  AvbVBMetaVerifyResult result = avb_vbmeta_image_verify(
      vbmeta, (size_t)footer.vbmeta_size, &embedded_key, &embedded_key_size);
  if (result != AVB_VBMETA_VERIFY_RESULT_OK)
    FAIL("FAILED: %s\n", avb_vbmeta_verify_result_to_string(result));

  /* Check public key */
  if (embedded_key_size != trusted_key_size ||
      memcmp(embedded_key, trusted_key, trusted_key_size) != 0)
    FAIL("FAILED: public key mismatch.\n");

  /* Parse header */
  AvbVBMetaImageHeader raw_hdr, hdr;
  memcpy(&raw_hdr, vbmeta, sizeof(raw_hdr));
  avb_vbmeta_image_header_to_host_byte_order(&raw_hdr, &hdr);

  /* Find hashtree descriptor */
  HashtreeInfo ht = {0};
  avb_descriptor_foreach(vbmeta, (size_t)footer.vbmeta_size, find_hashtree, &ht);

  if (!ht.found)
    FAIL("No hashtree descriptor found.\n");

  unsigned long data_blocks = (unsigned long)(ht.ht.image_size / ht.ht.data_block_size);
  unsigned long sectors     = data_blocks * (ht.ht.data_block_size / 512);
  unsigned long hash_start  = (unsigned long)(ht.ht.tree_offset / ht.ht.hash_block_size);

  if (dm_table_only) {
    printf("0 %lu verity %u %s %s %u %u %lu %lu %s ",
           sectors, ht.ht.dm_verity_version,
           device_path, device_path,
           ht.ht.data_block_size, ht.ht.hash_block_size,
           data_blocks, hash_start,
           (const char *)ht.ht.hash_algorithm);
    print_hex(ht.root_digest, ht.ht.root_digest_len);
    printf(" ");
    print_hex(ht.salt, ht.ht.salt_len);
    printf("\n");
    goto out;
  }

  printf("Verification:  OK\n");
  printf("Algorithm:     %s\n", algorithm_name(hdr.algorithm_type));
  printf("Rollback:      %lu\n", (unsigned long)hdr.rollback_index);
  printf("Partition:     %.*s\n", (int)ht.ht.partition_name_len, ht.partition_name);
  printf("Hash alg:      %s\n", ht.ht.hash_algorithm);
  printf("Data blocks:   %lu\n", data_blocks);
  printf("Data block sz: %u\n", ht.ht.data_block_size);
  printf("Hash block sz: %u\n", ht.ht.hash_block_size);
  printf("Hash offset:   %lu\n", (unsigned long)ht.ht.tree_offset);
  printf("Root digest:   "); print_hex(ht.root_digest, ht.ht.root_digest_len); printf("\n");
  printf("Salt:          "); print_hex(ht.salt, ht.ht.salt_len); printf("\n");

  printf("\ndm table:\n");
  printf("  0 %lu verity %u %s %s %u %u %lu %lu %s ",
         sectors, ht.ht.dm_verity_version,
         device_path, device_path,
         ht.ht.data_block_size, ht.ht.hash_block_size,
         data_blocks, hash_start,
         (const char *)ht.ht.hash_algorithm);
  print_hex(ht.root_digest, ht.ht.root_digest_len);
  printf(" ");
  print_hex(ht.salt, ht.ht.salt_len);
  printf("\n");

out:
  if (fp) fclose(fp);
  free(vbmeta);
  free(trusted_key);
  return ret;
}
