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
add_library(spdecode SHARED spdecode_transport.cpp)
target_include_directories(spdecode PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
set_target_properties(spdecode PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)
target_compile_options(spdecode PRIVATE -Wall -Wextra -Werror -fvisibility=hidden
  -fvisibility-inlines-hidden -fstack-protector-strong -D_FORTIFY_SOURCE=2
  -ffunction-sections -fdata-sections)
target_link_options(spdecode PRIVATE
  -Wl,-z,relro,-z,now
  -Wl,-z,noexecstack -Wl,--gc-sections -Wl,--exclude-libs,ALL
  "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/spdecode.exports"
  -Wl,-z,max-page-size=16384
  -Wl,-z,common-page-size=16384
)
