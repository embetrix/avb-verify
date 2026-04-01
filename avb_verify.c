// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * (C) Copyright 2026
 * Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
 *
 * avb_verify.c : AVB image verifier + dm-verity parameter extractor
 *
 * Usage:
 *   ./avb_verify <image> <pubkey.bin> [device]
 *   ./avb_verify --dm-table <image> <pubkey.bin> [device]
 *
 * Verifies the VBMeta signature, checks the public key, and prints
 * the dm-verity table. If [device] is given, it is used in the table
 * output instead of the image path.
 *
 * With --dm-table, prints only the raw dm table line (for piping to
 * dmsetup create).
 *
 * Extract the public key with:
 *   avbtool extract_public_key --key key.pem --output pubkey.bin
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef AVB_COMPILATION
#define AVB_COMPILATION
#endif
#include "avb/libavb/libavb.h"

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

static void print_hex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++)
    printf("%02x", data[i]);
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

/* Hashtree params extracted from the descriptor. */
typedef struct {
  bool found;
  AvbHashtreeDescriptor ht;
  const uint8_t *partition_name;
  const uint8_t *salt;
  const uint8_t *root_digest;
} HashtreeInfo;

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

#define FAIL(...) do { fprintf(stderr, __VA_ARGS__); ret = 1; goto out; } while (0)

int main(int argc, char *argv[]) {
  bool dm_table_only = false;
  int argi = 1;

  if (argi < argc && strcmp(argv[argi], "--dm-table") == 0) {
    dm_table_only = true;
    argi++;
  }

  if (argc - argi < 2 || argc - argi > 3) {
    fprintf(stderr,
      "Usage: avb_verify [--dm-table] <image> <pubkey.bin> [device]\n\n"
      "Verifies AVB signature and prints dm-verity parameters.\n"
      "If [device] is given, it replaces the image path in the dm table.\n"
      "With --dm-table, prints only the raw dm table line for piping.\n\n"
      "Examples:\n"
      "  avb_verify system.img pubkey.bin /dev/mmcblk0p2\n"
      "  avb_verify --dm-table system.img pubkey.bin /dev/sda1 | dmsetup create verity-system\n");
    return 1;
  }

  const char *image_path  = argv[argi];
  const char *pubkey_path = argv[argi + 1];
  const char *device_path = (argc - argi == 3) ? argv[argi + 2] : image_path;

  int ret = 0;
  uint8_t *trusted_key = NULL;
  uint8_t *vbmeta = NULL;
  FILE *fp = NULL;

  /* Load trusted public key. */
  size_t trusted_key_size;
  trusted_key = read_file_all(pubkey_path, &trusted_key_size);
  if (!trusted_key) return 1;

  /* Open image and read footer. */
  fp = fopen(image_path, "rb");
  if (!fp)
    FAIL("Error: cannot open '%s': %s\n", image_path, strerror(errno));

  fseek(fp, 0, SEEK_END);
  uint64_t image_size = (uint64_t)ftell(fp);
  if (image_size < AVB_FOOTER_SIZE)
    FAIL("Error: image too small for AVB footer.\n");

  AvbFooter raw_footer, footer;
  fseek(fp, (long)(image_size - AVB_FOOTER_SIZE), SEEK_SET);
  if (fread(&raw_footer, 1, AVB_FOOTER_SIZE, fp) != AVB_FOOTER_SIZE)
    FAIL("Error: could not read footer.\n");
  if (!avb_footer_validate_and_byteswap(&raw_footer, &footer))
    FAIL("Error: invalid AVB footer.\n");

  /* Read VBMeta blob. */
  vbmeta = malloc((size_t)footer.vbmeta_size);
  if (!vbmeta)
    FAIL("Error: out of memory.\n");
  fseek(fp, (long)footer.vbmeta_offset, SEEK_SET);
  if (fread(vbmeta, 1, (size_t)footer.vbmeta_size, fp) != footer.vbmeta_size)
    FAIL("Error: could not read VBMeta.\n");
  fclose(fp); fp = NULL;

  /* Verify VBMeta signature. */
  const uint8_t *embedded_key;
  size_t embedded_key_size;
  AvbVBMetaVerifyResult result = avb_vbmeta_image_verify(
      vbmeta, (size_t)footer.vbmeta_size, &embedded_key, &embedded_key_size);
  if (result != AVB_VBMETA_VERIFY_RESULT_OK)
    FAIL("FAILED: %s\n", avb_vbmeta_verify_result_to_string(result));

  /* Check public key. */
  if (embedded_key_size != trusted_key_size ||
      memcmp(embedded_key, trusted_key, trusted_key_size) != 0)
    FAIL("FAILED: public key mismatch.\n");

  /* Parse header. */
  AvbVBMetaImageHeader raw_hdr, hdr;
  memcpy(&raw_hdr, vbmeta, sizeof(raw_hdr));
  avb_vbmeta_image_header_to_host_byte_order(&raw_hdr, &hdr);

  /* Find hashtree descriptor. */
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
