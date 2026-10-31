#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace spdecode {
bool managedKeystoreAlias(const std::string& alias);
std::vector<std::string> managedKeystoreAliases(const std::vector<std::string>& all);
std::string preferredKeystoreAlias(const std::vector<std::string>& managed);
bool shouldPurgeKeystoreAlias(const std::string& alias,
                             const std::string& active,
                             std::int64_t nowMillis);
bool validEnrollmentChallenge(const std::string& challenge,
                              const std::string& level);
bool validKeyClaim(const std::string& key);
} // namespace spdecode
