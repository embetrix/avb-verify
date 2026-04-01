CC ?= gcc
CFLAGS = -Wall -Wextra -O2 -DAVB_COMPILATION -I. -Iavb/libavb/crypto

# libavb sources (using the standalone crypto/ implementation, no BoringSSL)
LIBAVB_DIR = avb/libavb
LIBAVB_SRCS = \
	$(LIBAVB_DIR)/avb_chain_partition_descriptor.c \
	$(LIBAVB_DIR)/avb_cmdline.c \
	$(LIBAVB_DIR)/avb_crc32.c \
	$(LIBAVB_DIR)/avb_crypto.c \
	$(LIBAVB_DIR)/avb_descriptor.c \
	$(LIBAVB_DIR)/avb_footer.c \
	$(LIBAVB_DIR)/avb_hash_descriptor.c \
	$(LIBAVB_DIR)/avb_hashtree_descriptor.c \
	$(LIBAVB_DIR)/avb_kernel_cmdline_descriptor.c \
	$(LIBAVB_DIR)/avb_mldsa.c \
	$(LIBAVB_DIR)/avb_property_descriptor.c \
	$(LIBAVB_DIR)/avb_rsa.c \
	$(LIBAVB_DIR)/avb_slot_verify.c \
	$(LIBAVB_DIR)/avb_sysdeps_posix.c \
	$(LIBAVB_DIR)/avb_util.c \
	$(LIBAVB_DIR)/avb_vbmeta_image.c \
	$(LIBAVB_DIR)/avb_version.c \
	$(LIBAVB_DIR)/crypto/sha256_impl.c \
	$(LIBAVB_DIR)/crypto/sha512_impl.c \
	$(LIBAVB_DIR)/crypto/mldsa_impl.c

TARGET = verify_avb

all: $(TARGET)

$(TARGET): verify_avb.c $(LIBAVB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: all clean
