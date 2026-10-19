cmake_minimum_required(VERSION 3.22.1)
project(spdecode LANGUAGES CXX)
# The validated public HTTPS API origin becomes a generated private C++ header.
# No quoting-sensitive compiler -D macro or Kotlin BuildConfig origin is needed.
if(NOT DEFINED SPDECODE_CLOUD_ORIGIN)
  set(SPDECODE_CLOUD_ORIGIN "")
endif()
configure_file(cloud_origin.h.in "${CMAKE_CURRENT_BINARY_DIR}/cloud_origin.h" @ONLY)
add_library(spdecode SHARED spdecode_transport.cpp)
target_include_directories(spdecode PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(spdecode PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
target_compile_options(spdecode PRIVATE -Wall -Wextra -Werror -fvisibility=hidden -fstack-protector-strong)
target_link_options(spdecode PRIVATE -Wl,-z,relro,-z,now)
