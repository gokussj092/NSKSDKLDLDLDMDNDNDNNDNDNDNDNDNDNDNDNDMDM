#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace spdecode {
struct PreparedEnvelope {
    std::vector<unsigned char> wire;
    std::uint64_t handle;
};

// Throws on any invalid state; exception boundaries are caught by JNI.
PreparedEnvelope hpkePrepare(int operation,
    const std::vector<unsigned char>& metadata,
    const std::vector<unsigned char>& attachment,
    const std::array<unsigned char,40>& publicPin);
std::vector<unsigned char> hpkeOpen(std::uint64_t handle, int status,
    const std::vector<unsigned char>& wire,
    const std::vector<unsigned char>& response);
void hpkeDiscard(std::uint64_t handle);
} // namespace spdecode
