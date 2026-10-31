cmake_minimum_required(VERSION 3.22.1)
project(spdecode LANGUAGES CXX)
# Per-build string encoding is reversible obfuscation, not secret encryption.
if(NOT DEFINED SPDECODE_CLOUD_ORIGIN)
  set(SPDECODE_CLOUD_ORIGIN "")
endif()
string(RANDOM LENGTH 3 ALPHABET "123456789" SPDECODE_STRING_KEY)
function(spdecode_encode INPUT OUTPUT)
  string(HEX "${INPUT}" HEX_VALUE)
  string(LENGTH "${HEX_VALUE}" HEX_LENGTH)
  set(ENCODED "")
  if(HEX_LENGTH GREATER 0)
    math(EXPR LAST "${HEX_LENGTH} - 2")
    foreach(OFFSET RANGE 0 ${LAST} 2)
      string(SUBSTRING "${HEX_VALUE}" ${OFFSET} 2 PAIR)
      math(EXPR INDEX "${OFFSET} / 2")
      math(EXPR VALUE "0x${PAIR} ^ ((${SPDECODE_STRING_KEY} + ${INDEX} * 31) & 255)")
      string(APPEND ENCODED "${VALUE},")
    endforeach()
  endif()
  set(${OUTPUT} "${ENCODED}0" PARENT_SCOPE)
endfunction()
spdecode_encode("${SPDECODE_CLOUD_ORIGIN}" SPDECODE_ORIGIN_BYTES)
spdecode_encode("/api/v2/transport" SPDECODE_PATH_BYTES)
configure_file(cloud_origin.h.in "${CMAKE_CURRENT_BINARY_DIR}/cloud_origin.h" @ONLY)
# Native RFC 9180 crypto from the official pinned Mbed TLS source archive.
# Compile on GitHub runner, never on the VPS. Do not use unverified HEAD.
include(FetchContent)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
FetchContent_Declare(spdecode_mbedtls
  URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2
  URL_HASH SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
)
FetchContent_MakeAvailable(spdecode_mbedtls)
# Opaque ELF basename reduces casual metadata; not a security boundary.
add_library(v7q3 SHARED spdecode_transport.cpp spdecode_hpke.cpp spdecode_security.cpp spdecode_session.cpp
    spdecode_keystore.cpp spdecode_keystore_policy.cpp spdecode_catalog.cpp spdecode_runtime_guard.cpp
    spdecode_code_integrity.cpp)
target_compile_definitions(v7q3 PRIVATE SPDECODE_ELF_GUARD=1)
target_link_libraries(v7q3 PRIVATE mbedcrypto dl)
target_include_directories(v7q3 PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(v7q3 PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
target_compile_options(v7q3 PRIVATE -Wall -Wextra -Werror -fvisibility=hidden
  -fvisibility-inlines-hidden -fstack-protector-strong -D_FORTIFY_SOURCE=2
  -ffunction-sections -fdata-sections)
# Backward-compatible ARM64 branch protection; CFI requires staged JNI/ABI QA.
if(ANDROID_ABI STREQUAL "arm64-v8a")
  target_compile_options(v7q3 PRIVATE -mbranch-protection=standard)
endif()
option(SPDECODE_ENABLE_CFI "Enable Clang LTO/CFI for staged QA" OFF)
if(SPDECODE_ENABLE_CFI AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  target_compile_options(v7q3 PRIVATE -flto=thin -fsanitize=cfi)
  target_link_options(v7q3 PRIVATE -flto=thin -fsanitize=cfi)
endif()
target_link_options(v7q3 PRIVATE
  -Wl,-z,relro,-z,now
  -Wl,-z,noexecstack -Wl,--gc-sections -Wl,--exclude-libs,ALL
  "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/spdecode.exports"
  -Wl,-z,max-page-size=16384
  -Wl,-z,common-page-size=16384
)
