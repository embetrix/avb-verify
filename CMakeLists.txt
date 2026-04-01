cmake_minimum_required(VERSION 3.10)
project(avb_verify C)

set(LIBAVB_DIR avb/libavb)

add_executable(avb_verify
    avb_verify.c
    ${LIBAVB_DIR}/avb_chain_partition_descriptor.c
    ${LIBAVB_DIR}/avb_cmdline.c
    ${LIBAVB_DIR}/avb_crc32.c
    ${LIBAVB_DIR}/avb_crypto.c
    ${LIBAVB_DIR}/avb_descriptor.c
    ${LIBAVB_DIR}/avb_footer.c
    ${LIBAVB_DIR}/avb_hash_descriptor.c
    ${LIBAVB_DIR}/avb_hashtree_descriptor.c
    ${LIBAVB_DIR}/avb_kernel_cmdline_descriptor.c
    ${LIBAVB_DIR}/avb_mldsa.c
    ${LIBAVB_DIR}/avb_property_descriptor.c
    ${LIBAVB_DIR}/avb_rsa.c
    ${LIBAVB_DIR}/avb_slot_verify.c
    ${LIBAVB_DIR}/avb_sysdeps_posix.c
    ${LIBAVB_DIR}/avb_util.c
    ${LIBAVB_DIR}/avb_vbmeta_image.c
    ${LIBAVB_DIR}/avb_version.c
    ${LIBAVB_DIR}/crypto/sha256_impl.c
    ${LIBAVB_DIR}/crypto/sha512_impl.c
    ${LIBAVB_DIR}/crypto/mldsa_impl.c
)

target_compile_definitions(avb_verify PRIVATE AVB_COMPILATION)
target_include_directories(avb_verify PRIVATE ${CMAKE_SOURCE_DIR} ${LIBAVB_DIR}/crypto)
target_compile_options(avb_verify PRIVATE -Wall -Wextra)

enable_testing()
add_test(NAME integration COMMAND ${CMAKE_SOURCE_DIR}/avb_verify_test.sh
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
set_tests_properties(integration PROPERTIES
    ENVIRONMENT "avb_verify=$<TARGET_FILE:avb_verify>")
