cmake_minimum_required(VERSION 3.10)
project(avb_verify C)

# Try system-installed libavb first, fall back to submodule
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBAVB QUIET libavb)
endif()

add_executable(avb_verify avb_verify.c)
target_compile_options(avb_verify PRIVATE -Wall -Wextra)

if(LIBAVB_FOUND)
    message(STATUS "Using system libavb: ${LIBAVB_LINK_LIBRARIES}")
    target_include_directories(avb_verify PRIVATE ${LIBAVB_INCLUDE_DIRS})
    target_link_libraries(avb_verify PRIVATE ${LIBAVB_LINK_LIBRARIES})
else()
    message(STATUS "System libavb not found, using avb submodule")
    set(LIBAVB_DIR avb/libavb)
    target_sources(avb_verify PRIVATE
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
    target_include_directories(avb_verify PRIVATE ${CMAKE_SOURCE_DIR}/avb ${LIBAVB_DIR}/crypto)
endif()

install(TARGETS avb_verify RUNTIME DESTINATION bin)

enable_testing()
add_test(NAME integration COMMAND ${CMAKE_SOURCE_DIR}/avb_verify_test.sh
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
set_tests_properties(integration PROPERTIES
    ENVIRONMENT "avb_verify=$<TARGET_FILE:avb_verify>")

add_test(NAME avb_sign COMMAND ${CMAKE_SOURCE_DIR}/avb_sign_test.sh
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
set_tests_properties(avb_sign PROPERTIES
    ENVIRONMENT "avb_verify=$<TARGET_FILE:avb_verify>")
