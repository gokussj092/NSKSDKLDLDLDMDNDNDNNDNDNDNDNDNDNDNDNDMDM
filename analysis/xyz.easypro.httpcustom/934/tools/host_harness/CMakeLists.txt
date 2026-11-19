# Host harness for the offline native HTTP Custom decoder (n15).
# Mbed TLS is fetched pinned (3.6.7 tarball + SHA-256, same as the app's
# android/app/src/main/cpp/CMakeLists.txt). nlohmann/json and Argon2 use
# the system packages when present (Ubuntu: nlohmann-json3-dev,
# libargon2-dev) and fall back to the same pinned git sources as the app.
# Build out of tree (no Android NDK needed):
#   cmake -S <this dir> -B /tmp/hc-n15-harness-build -DCMAKE_BUILD_TYPE=Release
#   cmake --build /tmp/hc-n15-harness-build -j
# Produces /tmp/hc-n15-harness-build/hc_harness.
cmake_minimum_required(VERSION 3.22.1)
project(hc_n15_harness LANGUAGES C CXX)

set(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../..")
set(CPP_DIR "${REPO_ROOT}/android/app/src/main/cpp")

include(FetchContent)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(SPDECODE_MBEDTLS_ARCHIVE "$ENV{SPDECODE_MBEDTLS_ARCHIVE}")
if(SPDECODE_MBEDTLS_ARCHIVE AND EXISTS "${SPDECODE_MBEDTLS_ARCHIVE}")
  set(SPDECODE_MBEDTLS_URL "file://${SPDECODE_MBEDTLS_ARCHIVE}")
else()
  set(SPDECODE_MBEDTLS_URL
      "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2")
endif()
FetchContent_Declare(spdecode_mbedtls
  URL "${SPDECODE_MBEDTLS_URL}"
  URL_HASH SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
)
FetchContent_MakeAvailable(spdecode_mbedtls)

# nlohmann/json: system package first (header-only), pinned git fallback.
find_package(nlohmann_json 3.11 QUIET)
if(NOT nlohmann_json_FOUND)
  FetchContent_Declare(spdecode_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG 9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03)
  FetchContent_MakeAvailable(spdecode_json)
endif()

# Argon2: system reference library first, pinned git fallback.
find_path(ARGON2_INCLUDE_DIR NAMES argon2.h)
find_library(ARGON2_LIBRARY NAMES argon2)
if(ARGON2_INCLUDE_DIR AND ARGON2_LIBRARY)
  add_library(spdecode_argon2_ref INTERFACE)
  target_include_directories(spdecode_argon2_ref INTERFACE ${ARGON2_INCLUDE_DIR})
  target_link_libraries(spdecode_argon2_ref INTERFACE ${ARGON2_LIBRARY})
else()
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
endif()

add_executable(hc_harness
  main.cpp
  "${CPP_DIR}/spdecode_http_custom.cpp"
  "${CPP_DIR}/spdecode_http_custom_legacy.cpp")
target_include_directories(hc_harness PRIVATE "${CPP_DIR}")
target_link_libraries(hc_harness PRIVATE mbedcrypto spdecode_argon2_ref nlohmann_json::nlohmann_json)
target_compile_features(hc_harness PRIVATE cxx_std_17)
target_compile_options(hc_harness PRIVATE -Wall -Wextra -Werror
    -fstack-protector-strong -D_FORTIFY_SOURCE=2)
