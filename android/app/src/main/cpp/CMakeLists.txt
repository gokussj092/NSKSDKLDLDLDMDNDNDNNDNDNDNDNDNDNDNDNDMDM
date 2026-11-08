cmake_minimum_required(VERSION 3.22.1)
project(spdecode LANGUAGES C CXX)
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
# Independent offline target; never embed Cloud transport or endpoints.
option(SPDECODE_OFFLINE_NATIVE "Build standalone offline native engine" OFF)
if(SPDECODE_OFFLINE_NATIVE)
  # Pinned, reproducible sources: JSON is header-only, Argon2id is the
  # reference implementation. Neither is needed by the Cloud APK.
  FetchContent_Declare(spdecode_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG 9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03)
  FetchContent_MakeAvailable(spdecode_json)
  FetchContent_Declare(spdecode_argon2
    GIT_REPOSITORY https://github.com/P-H-C/phc-winner-argon2.git
    GIT_TAG 62358ba2123abd17fccf2a108a301d4b52c01a7c)
  FetchContent_GetProperties(spdecode_argon2)
  if(NOT spdecode_argon2_POPULATED)
    FetchContent_Populate(spdecode_argon2)
  endif()
  add_library(spdecode_argon2_ref STATIC
    ${spdecode_argon2_SOURCE_DIR}/src/argon2.c
    ${spdecode_argon2_SOURCE_DIR}/src/core.c
    ${spdecode_argon2_SOURCE_DIR}/src/encoding.c
    ${spdecode_argon2_SOURCE_DIR}/src/ref.c
    ${spdecode_argon2_SOURCE_DIR}/src/blake2/blake2b.c)
  target_compile_definitions(spdecode_argon2_ref PRIVATE ARGON2_NO_THREADS)
  target_include_directories(spdecode_argon2_ref PUBLIC
    ${spdecode_argon2_SOURCE_DIR}/include PRIVATE
    ${spdecode_argon2_SOURCE_DIR}/src)
  set_target_properties(spdecode_argon2_ref PROPERTIES POSITION_INDEPENDENT_CODE ON)
  # Reconstruct only audited, source-controlled NPV constants on the host.
  # The Android APK receives raw C++ bytes, never Python, pickle or scripts.
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  set(SPDECODE_NPV_TABLES "${CMAKE_CURRENT_BINARY_DIR}/spdecode_npv_tables.h")
  execute_process(
    COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../scripts/build_offline_npv_tables.py"
      --output "${SPDECODE_NPV_TABLES}"
    RESULT_VARIABLE SPDECODE_NPV_TABLES_RESULT
    OUTPUT_VARIABLE SPDECODE_NPV_TABLES_LOG
    ERROR_VARIABLE SPDECODE_NPV_TABLES_ERROR)
  if(NOT SPDECODE_NPV_TABLES_RESULT EQUAL 0)
    message(FATAL_ERROR "NPV native tables validation failed: ${SPDECODE_NPV_TABLES_ERROR}")
  endif()
  message(STATUS "${SPDECODE_NPV_TABLES_LOG}")
  add_library(offdecode SHARED
    spdecode_offline_native.cpp
    spdecode_http_custom.cpp
    spdecode_http_custom_legacy.cpp
    spdecode_http_injector.cpp
    spdecode_npv_text.cpp
    spdecode_npv_whitebox.cpp
    spdecode_npv_signed.cpp
    spdecode_npv_legacy.cpp)
  target_include_directories(offdecode PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
  target_link_libraries(offdecode PRIVATE mbedcrypto spdecode_argon2_ref nlohmann_json::nlohmann_json z)
  target_compile_features(offdecode PRIVATE cxx_std_17)
  target_compile_options(offdecode PRIVATE -Wall -Wextra -Werror
      -fvisibility=hidden -fvisibility-inlines-hidden
      -fstack-protector-strong -D_FORTIFY_SOURCE=2)
  target_link_options(offdecode PRIVATE -Wl,-z,relro,-z,now
      -Wl,-z,noexecstack -Wl,-z,max-page-size=16384)
  return()
endif()
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
