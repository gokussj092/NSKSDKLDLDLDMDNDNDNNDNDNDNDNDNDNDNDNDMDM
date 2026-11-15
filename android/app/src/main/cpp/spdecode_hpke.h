#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace spdecode {
// Binary data is permitted only on the existing VPN file operation (5)
// and the F7 QA APK fragment operation (22). All other V2 requests
// remain metadata-only, including F7 start, finish and result.
constexpr std::size_t hpkeAttachmentLimit(int operation) noexcept {
    return operation == 5 ? 8U * 1024U * 1024U :
           operation == 22 ? 2U * 1024U * 1024U : 0U;
}
constexpr bool hpkeAttachmentAllowed(int operation, std::size_t bytes) noexcept {
    const auto max = hpkeAttachmentLimit(operation);
    return max == 0U ? bytes == 0U : bytes > 0U && bytes <= max;
}

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
