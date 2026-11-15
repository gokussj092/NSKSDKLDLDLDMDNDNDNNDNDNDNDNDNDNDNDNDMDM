#pragma once
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
namespace spdecode::admin {
struct Plan { std::string path; const char* method; std::size_t max_response; };
// Only route IDs verified in the server tree are accepted. No arbitrary URLs.
std::optional<Plan> plan(std::string_view operation, std::string_view query,
                         int page, std::size_t body_size);
// Single source of truth for the panel origin and the session contract.
// Kotlin never hardcodes these values; it reads them through JNI.
inline constexpr const char* kAdminOrigin = "https://panel.spdecode.xyz";
inline constexpr const char* kAdminCookiePath = "/api/admin";
inline constexpr const char* kAdminSessionCookie = "spdecode_admin_session";
inline constexpr const char* kStaffSessionCookie = "spdecode_staff_session";
}
