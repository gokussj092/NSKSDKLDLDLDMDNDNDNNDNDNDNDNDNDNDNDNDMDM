#pragma once
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

namespace spdecode {
// Native RAM-only session cache. Admission policy is enforced by the VPS.
class SessionCache final {
public:
    using Clock = std::chrono::steady_clock;
    void store(const std::string& bearer, std::int64_t ttlSeconds,
               bool actionIntegrity, Clock::time_point now = Clock::now());
    std::string get(Clock::time_point now = Clock::now());
    bool requiresActionIntegrityFor(const std::string& bearer) const;
    void configureAction(const std::string& bearer, std::int64_t project, bool inlineMode);
    std::int64_t inlineActionProject(const std::string& bearer) const;
    void clear();
    void clearIfMatches(const std::string& bearer);
    ~SessionCache();
private:
    void clearLocked();
    mutable std::mutex mutex_;
    std::string bearer_;
    Clock::time_point deadline_{};
    bool actionIntegrity_ = true;
    bool inlineAction_ = false;
    std::int64_t actionProject_ = 0;
};
SessionCache& sharedSession();
} // namespace spdecode
