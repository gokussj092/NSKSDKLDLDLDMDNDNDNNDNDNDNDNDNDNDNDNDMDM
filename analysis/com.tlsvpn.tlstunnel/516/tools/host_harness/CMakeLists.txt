# Host harness for the offline native TLS Tunnel decoder.
# Mbed TLS is fetched pinned (3.6.7 tarball + SHA-256, same as the app's
# android/app/src/main/cpp/CMakeLists.txt). nlohmann/json uses the system
# package when present (Ubuntu: nlohmann-json3-dev) and falls back to the
# same pinned git source as the app.
# Build out of tree (no Android NDK needed):
#   cmake -S <this dir> -B /tmp/tls-harness-build -DCMAKE_BUILD_TYPE=Release
#   cmake --build /tmp/tls-harness-build -j
# Produces /tmp/tls-harness-build/tls_harness.
cmake_minimum_required(VERSION 3.22.1)
project(tls_harness LANGUAGES C CXX)

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

find_package(nlohmann_json 3.11 QUIET)
if(NOT nlohmann_json_FOUND)
  FetchContent_Declare(spdecode_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG 9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03)
  FetchContent_MakeAvailable(spdecode_json)
endif()

add_executable(tls_harness
  main.cpp
  "${CPP_DIR}/spdecode_tls_tunnel.cpp")
target_include_directories(tls_harness PRIVATE "${CPP_DIR}")
target_link_libraries(tls_harness PRIVATE mbedcrypto nlohmann_json::nlohmann_json)
target_compile_features(tls_harness PRIVATE cxx_std_17)
target_compile_options(tls_harness PRIVATE -Wall -Wextra -Werror
    -fstack-protector-strong -D_FORTIFY_SOURCE=2)
