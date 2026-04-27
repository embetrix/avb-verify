// SPDX-License-Identifier: GPL-2.0-only
/*
 * (C) Copyright 2026
 * Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
 *
 * avb_verify -- AVB vbmeta verifier and dm-verity table extractor
 *
 * Reads an image file or block device, locates the AVB footer (scanning
 * forward in 1 MiB chunks when it is not at the last block), verifies
 * the vbmeta PKCS#7 signature, and checks the embedded public key against
 * a trusted reference key.
 *
 * Output modes:
 *   default        human-readable verification summary + indented dm-verity
 *                  table suitable for review
 *   -t/--dm-table  raw dm-verity table line only, suitable for piping
 *                  directly to "dmsetup create"
 *
 * Root hash signature (CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG):
 *   When the vbmeta image contains a "roothash_sig" property (a
 *   DER-encoded PKCS#7 signature over the root hash), it is loaded into
 *   the process session keyring via add_key(2) under the description
 *   "avb_roothash_sig.<partition>".  The dm-verity table is then extended
 *   with "root_hash_sig_key_desc <desc>" so the kernel can verify the
 *   root hash independently at mount time.
 *
 * Prepare the trusted public key with:
 *   avbtool extract_public_key --key key.pem --output pubkey.bin
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/keyctl.h>
#include <linux/magic.h>

#include <libavb/libavb.h>

#define FAIL(...) \
	do { fprintf(stderr, __VA_ARGS__); ret = 1; goto out; } while (0)

/* avbtool block size — footer is aligned at the end of a 4 KiB block */
#define AVB_BLOCK_SIZE		4096

/* Scan chunk size: 1 MiB */
#define SCAN_CHUNK_SIZE		(1024 * 1024)

/*
 * Maximum number of blocks to scan when searching for the AVB footer.
 * Covers block devices up to 2048 MiB larger than the actual signed
 * image.  Increase if needed.
 */
#define FOOTER_SCAN_MAX_BLOCKS	((2048ULL * 1024 * 1024) / AVB_BLOCK_SIZE)

#define ROOTHASH_SIG_KEY_PREFIX	"avb_roothash_sig."
#define AVB_PART_NAME_MAX_LEN	128

/* Hashtree descriptor fields extracted from vbmeta */
typedef struct {
	bool found;
	AvbHashtreeDescriptor ht;
	const uint8_t *partition_name;
	const uint8_t *salt;
	const uint8_t *root_digest;
} HashtreeInfo;

/* Little-endian field readers (ext4/erofs superblocks are LE) */
static uint16_t read_le16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_le64(const uint8_t *p)
{
	return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

/*
 * Detect filesystem size from superblock (ext2/ext3/ext4, erofs or squashfs).
 * Returns the filesystem size in bytes, or 0 if unknown.
 */
static uint64_t detect_fs_size(FILE *fp)
{
	uint8_t sb[4096];

	fseek(fp, 0, SEEK_SET);
	if (fread(sb, 1, sizeof(sb), fp) < 2048)
		return 0;

	/* ext2/ext3/ext4: superblock at offset 1024, magic at sb+56 */
	if (read_le16(sb + 1024 + 56) == EXT4_SUPER_MAGIC) {
		uint32_t s_blocks_count_lo = read_le32(sb + 1024 + 4);
		uint32_t s_log_block_size  = read_le32(sb + 1024 + 24);
		uint64_t block_size        = 1024ULL << s_log_block_size;

		return (uint64_t)s_blocks_count_lo * block_size;
	}

	/* erofs: superblock at offset 1024 */
	if (read_le32(sb + 1024) == EROFS_SUPER_MAGIC_V1) {
		uint8_t  blkszbits = sb[1024 + 12];
		uint32_t blocks    = read_le32(sb + 1024 + 36);

		return (uint64_t)blocks << blkszbits;
	}

	/* squashfs: magic at offset 0, bytes_used at offset 40 */
	if (read_le32(sb) == SQUASHFS_MAGIC)
		return read_le64(sb + 40);

	return 0;
}

static void print_hex(const uint8_t *data, size_t len)
{
	for (size_t i = 0; i < len; i++)
		printf("%02x", data[i]);
}

/*
 * Parse a hex string into a byte buffer.
 * Returns the number of bytes written, or -1 on error.
 */
static int parse_hex(const char *hex, uint8_t *out, size_t out_max)
{
	size_t len = strlen(hex);

	if (len % 2 != 0 || len / 2 > out_max)
		return -1;
	for (size_t i = 0; i < len; i += 2) {
		unsigned int byte;

		if (sscanf(hex + i, "%2x", &byte) != 1)
			return -1;
		out[i / 2] = (uint8_t)byte;
	}
	return (int)(len / 2);
}

static uint8_t *read_file_all(const char *path, size_t *out_size)
{
	uint8_t *buf;
	FILE *fp;
	long len;

	fp = fopen(path, "rb");
	if (!fp) {
		fprintf(stderr, "Error: cannot open '%s': %s\n",
			path, strerror(errno));
		return NULL;
	}
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	if (len < 0) {
		fclose(fp);
		return NULL;
	}
	rewind(fp);
	buf = malloc((size_t)len);
	if (!buf) {
		fclose(fp);
		return NULL;
	}
	if (fread(buf, 1, (size_t)len, fp) != (size_t)len) {
		free(buf);
		fclose(fp);
		return NULL;
	}
	fclose(fp);
	*out_size = (size_t)len;
	return buf;
}

static const char *algorithm_name(uint32_t type)
{
	switch (type) {
	case AVB_ALGORITHM_TYPE_SHA256_RSA2048: return "SHA256_RSA2048";
	case AVB_ALGORITHM_TYPE_SHA256_RSA4096: return "SHA256_RSA4096";
	case AVB_ALGORITHM_TYPE_SHA256_RSA8192: return "SHA256_RSA8192";
	case AVB_ALGORITHM_TYPE_SHA512_RSA2048: return "SHA512_RSA2048";
	case AVB_ALGORITHM_TYPE_SHA512_RSA4096: return "SHA512_RSA4096";
	case AVB_ALGORITHM_TYPE_SHA512_RSA8192: return "SHA512_RSA8192";
	case AVB_ALGORITHM_TYPE_MLDSA65:        return "MLDSA65";
	case AVB_ALGORITHM_TYPE_MLDSA87:        return "MLDSA87";
	default:                                return "NONE";
	}
}

/* Descriptor callback to find the first hashtree descriptor. */
static bool find_hashtree(const AvbDescriptor *desc, void *user_data)
{
	HashtreeInfo *info = (HashtreeInfo *)user_data;
	AvbDescriptor header;
	const uint8_t *p;

	if (!avb_descriptor_validate_and_byteswap(desc, &header))
		return true;
	if (header.tag != AVB_DESCRIPTOR_TAG_HASHTREE)
		return true;
	if (!avb_hashtree_descriptor_validate_and_byteswap(
			(const AvbHashtreeDescriptor *)desc, &info->ht))
		return true;
	p = (const uint8_t *)desc + sizeof(AvbHashtreeDescriptor);
	info->partition_name = p;
	info->salt           = p + info->ht.partition_name_len;
	info->root_digest    = info->salt + info->ht.salt_len;
	info->found          = true;
	return false;
}

/*
 * Load the PKCS#7 root hash signature from a vbmeta property into the
 * session keyring. Returns 1 if loaded, 0 if not present, -1 on error
 * (errno is set by the failed add_key syscall).
 */
static int load_roothash_sig(const uint8_t *vbmeta, size_t vbmeta_size,
			     const HashtreeInfo *ht, bool verbose,
			     char *key_desc, size_t key_desc_size)
{
	const char *sig_data;
	size_t sig_size = 0;
	long key_id;

	sig_data = avb_property_lookup(vbmeta, vbmeta_size,
				       "roothash_sig", 0, &sig_size);
	if (!sig_data || sig_size == 0)
		return 0;

	snprintf(key_desc, key_desc_size, "%s%.*s",
		 ROOTHASH_SIG_KEY_PREFIX,
		 (int)ht->ht.partition_name_len, ht->partition_name);
	key_id = syscall(__NR_add_key, "user", key_desc,
			 sig_data, sig_size, KEY_SPEC_USER_SESSION_KEYRING);
	if (key_id < 0)
		return -1;

	if (verbose)
		fprintf(stderr,
			"Roothash signature loaded into keyring: %s (%zu bytes)\n",
			key_desc, sig_size);
	return 1;
}

static void print_verity_table(const char *prefix, const char *device_path,
				unsigned long sectors, const HashtreeInfo *ht,
				unsigned long data_blocks,
				unsigned long hash_start,
				bool has_roothash_sig,
				const char *sig_key_desc)
{
	printf("%s0 %lu verity %u %s %s %u %u %lu %lu %s ",
	       prefix, sectors, ht->ht.dm_verity_version,
	       device_path, device_path,
	       ht->ht.data_block_size, ht->ht.hash_block_size,
	       data_blocks, hash_start,
	       (const char *)ht->ht.hash_algorithm);
	print_hex(ht->root_digest, ht->ht.root_digest_len);
	printf(" ");
	print_hex(ht->salt, ht->ht.salt_len);
	if (has_roothash_sig)
		printf(" 2 root_hash_sig_key_desc %s", sig_key_desc);
	printf("\n");
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -d <device> -k <pubkey.bin> [-x <sha256>] [-t] [-h]\n\n"
		"Verify AVB signature and print dm-verity parameters.\n\n"
		"Options:\n"
		"  -d, --device <path>             Image file or block device (required)\n"
		"  -k, --pubkey <path>             AVB public key file (required)\n"
		"  -t, --dm-table                  Print only the raw dm table line\n"
		"  -h, --help                      Show this help\n\n"
		"If a 'roothash_sig' property (PKCS#7) is found in the vbmeta image,\n"
		"it is loaded into the session keyring and 'root_hash_sig_key_desc'\n"
		"is appended to the dm-verity table for kernel-level verification.\n\n"
		"Examples:\n"
		"  %s -d /dev/mmcblk0p2 -k pubkey.bin\n"
		"  %s -t -d /dev/mmcblk0p2 -k pubkey.bin | dmsetup create verity-system\n",
		prog, prog, prog);
}

int main(int argc, char *argv[])
{
	static const struct option long_opts[] = {
		{ "pubkey",        required_argument, NULL, 'k' },
		{ "device",        required_argument, NULL, 'd' },
		{ "dm-table",      no_argument,       NULL, 't' },
		{ "help",          no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	bool dm_table_only = false;
	const char *device_path = NULL;
	const char *pubkey_path = NULL;
	int ret = 0;
	int opt;
	uint8_t *trusted_key = NULL;
	size_t trusted_key_size = 0;
	uint8_t *vbmeta = NULL;
	FILE *fp = NULL;
	uint64_t image_size;
	AvbFooter raw_footer, footer;
	bool footer_found = false;
	struct timespec ts_start, ts_end;
	double scan_ms;
	const uint8_t *embedded_key;
	size_t embedded_key_size;
	AvbVBMetaVerifyResult result;
	AvbVBMetaImageHeader raw_hdr, hdr;
	HashtreeInfo ht = { 0 };
	char sig_key_desc[AVB_PART_NAME_MAX_LEN + sizeof(ROOTHASH_SIG_KEY_PREFIX)];
	int sig_rc;
	bool has_roothash_sig;
	unsigned long data_blocks;
	unsigned long sectors;
	unsigned long hash_start;

	memset(sig_key_desc, 0, sizeof(sig_key_desc));

	while ((opt = getopt_long(argc, argv, "d:k:th", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'd': device_path = optarg;  break;
		case 'k': pubkey_path = optarg;  break;
		case 't': dm_table_only = true;  break;
		case 'h':
		default:
			usage(argv[0]);
			return (opt == 'h') ? 0 : 1;
		}
	}

	if (!device_path || !pubkey_path) {
		usage(argv[0]);
		return 1;
	}

	/* Load trusted public key */
	trusted_key = read_file_all(pubkey_path, &trusted_key_size);
	if (!trusted_key)
		return 1;

	/*
	 * Open image and find AVB footer.  Try the last 64 bytes first
	 * (standard location).  If not found, scan forward in 1 MiB chunks
	 * so that images created with --partition_size 0 work on larger
	 * block devices.
	 */
	fp = fopen(device_path, "rb");
	if (!fp)
		FAIL("Error: cannot open '%s': %s\n",
		     device_path, strerror(errno));

	fseek(fp, 0, SEEK_END);
	image_size = (uint64_t)ftell(fp);
	if (image_size < AVB_FOOTER_SIZE)
		FAIL("Error: image too small for AVB footer.\n");

	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	/* Fast path: footer at end of file/device */
	fseek(fp, (long)(image_size - AVB_FOOTER_SIZE), SEEK_SET);
	if (fread(&raw_footer, 1, AVB_FOOTER_SIZE, fp) == AVB_FOOTER_SIZE &&
	    memcmp(raw_footer.magic, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) == 0 &&
	    avb_footer_validate_and_byteswap(&raw_footer, &footer))
		footer_found = true;

	/* Slow path: scan forward in 1 MiB chunks */
	if (!footer_found) {
		uint64_t max_scan  = FOOTER_SCAN_MAX_BLOCKS * (uint64_t)AVB_BLOCK_SIZE;
		uint64_t scan_end  = (image_size < max_scan) ? image_size : max_scan;
		uint64_t fs_size   = detect_fs_size(fp);
		uint64_t scan_start = 0;
		uint8_t *chunk;

		if (fs_size > SCAN_CHUNK_SIZE)
			scan_start = (fs_size - SCAN_CHUNK_SIZE) &
				     ~(uint64_t)(AVB_BLOCK_SIZE - 1);

		chunk = malloc(SCAN_CHUNK_SIZE);
		if (!chunk)
			FAIL("Error: out of memory.\n");

		for (uint64_t pos = scan_start;
		     pos < scan_end && !footer_found; ) {
			uint64_t chunk_len = scan_end - pos;
			size_t got;

			if (chunk_len > SCAN_CHUNK_SIZE)
				chunk_len = SCAN_CHUNK_SIZE;

			fseek(fp, (long)pos, SEEK_SET);
			got = fread(chunk, 1, (size_t)chunk_len, fp);
			if (got < AVB_BLOCK_SIZE)
				break;

			/* Check each 4 KiB footer position within this chunk */
			uint64_t last_off = (got / AVB_BLOCK_SIZE) *
					    AVB_BLOCK_SIZE - AVB_FOOTER_SIZE;

			for (uint64_t off = AVB_BLOCK_SIZE - AVB_FOOTER_SIZE;
			     off <= last_off; off += AVB_BLOCK_SIZE) {
				if (memcmp(chunk + off, AVB_FOOTER_MAGIC,
					   AVB_FOOTER_MAGIC_LEN) != 0)
					continue;
				memcpy(&raw_footer, chunk + off, AVB_FOOTER_SIZE);
				if (avb_footer_validate_and_byteswap(&raw_footer,
								     &footer)) {
					footer_found = true;
					break;
				}
			}
			pos += got;
		}
		free(chunk);
	}

	clock_gettime(CLOCK_MONOTONIC, &ts_end);
	scan_ms = (ts_end.tv_sec - ts_start.tv_sec) * 1000.0 +
		  (ts_end.tv_nsec - ts_start.tv_nsec) / 1e6;
	if (!dm_table_only)
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
	fclose(fp);
	fp = NULL;

	/* Verify VBMeta signature */
	result = avb_vbmeta_image_verify(vbmeta, (size_t)footer.vbmeta_size,
					 &embedded_key, &embedded_key_size);
	if (result != AVB_VBMETA_VERIFY_RESULT_OK)
		FAIL("FAILED: %s\n", avb_vbmeta_verify_result_to_string(result));

	/* Check public key */
	if (embedded_key_size != trusted_key_size ||
	    memcmp(embedded_key, trusted_key, trusted_key_size) != 0)
		FAIL("FAILED: public key mismatch.\n");

	/* Parse vbmeta header */
	memcpy(&raw_hdr, vbmeta, sizeof(raw_hdr));
	avb_vbmeta_image_header_to_host_byte_order(&raw_hdr, &hdr);

	/* Find hashtree descriptor */
	avb_descriptor_foreach(vbmeta, (size_t)footer.vbmeta_size,
			       find_hashtree, &ht);
	if (!ht.found)
		FAIL("No hashtree descriptor found.\n");

	sig_rc = load_roothash_sig(vbmeta, (size_t)footer.vbmeta_size,
				   &ht, !dm_table_only,
				   sig_key_desc, sizeof(sig_key_desc));
	if (sig_rc < 0)
		FAIL("Error: add_key to session keyring: %s\n", strerror(errno));
	has_roothash_sig = (sig_rc > 0);

	data_blocks = (unsigned long)(ht.ht.image_size / ht.ht.data_block_size);
	sectors     = data_blocks * (ht.ht.data_block_size / 512);
	hash_start  = (unsigned long)(ht.ht.tree_offset / ht.ht.hash_block_size);

	if (dm_table_only) {
		print_verity_table("", device_path, sectors, &ht,
				   data_blocks, hash_start,
				   has_roothash_sig, sig_key_desc);
		goto out;
	}

	printf("Verification:  OK\n");
	printf("Algorithm:     %s\n", algorithm_name(hdr.algorithm_type));
	printf("Rollback:      %lu\n", (unsigned long)hdr.rollback_index);
	printf("Partition:     %.*s\n",
	       (int)ht.ht.partition_name_len, ht.partition_name);
	printf("Hash alg:      %s\n", ht.ht.hash_algorithm);
	printf("Data blocks:   %lu\n", data_blocks);
	printf("Data block sz: %u\n", ht.ht.data_block_size);
	printf("Hash block sz: %u\n", ht.ht.hash_block_size);
	printf("Hash offset:   %lu\n", (unsigned long)ht.ht.tree_offset);
	printf("Root digest:   ");
	print_hex(ht.root_digest, ht.ht.root_digest_len);
	printf("\n");
	printf("Salt:          ");
	print_hex(ht.salt, ht.ht.salt_len);
	printf("\n");
	if (has_roothash_sig)
		printf("Roothash sig:  %s\n", sig_key_desc);

	printf("\ndm table:\n");
	print_verity_table("  ", device_path, sectors, &ht,
			   data_blocks, hash_start,
			   has_roothash_sig, sig_key_desc);

out:
	if (fp)
		fclose(fp);
	free(vbmeta);
	free(trusted_key);
	return ret;
}
