#include "spdecode_session.h"
#include <mbedtls/platform_util.h>
#include <chrono>
#include <stdexcept>

namespace spdecode {
namespace {
bool validBearer(const std::string& bearer) {
    if(bearer.size()<3 || bearer.size()>2048) return false;
    const auto dot=bearer.find('.');
    if(dot==0 || dot==std::string::npos || dot==bearer.size()-1 ||
       bearer.find('.',dot+1)!=std::string::npos) return false;
    for(unsigned char c:bearer)
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
             (c>='0'&&c<='9')||c=='-'||c=='_'||c=='.')) return false;
    return true;
}
void scrub(std::string& value) {
    if(!value.empty())mbedtls_platform_zeroize(value.data(),value.size());
    value.clear();
}
} // namespace
void SessionCache::clearLocked() {
    scrub(bearer_);
    deadline_=Clock::time_point{};
    actionIntegrity_=true;
    inlineAction_=false;
    actionProject_=0;
}
SessionCache::~SessionCache() {
    std::lock_guard<std::mutex> guard(mutex_);
    clearLocked();
}
void SessionCache::store(const std::string& bearer,std::int64_t ttlSeconds,
                         bool actionIntegrity,Clock::time_point now) {
    if(!validBearer(bearer) || ttlSeconds<1 || ttlSeconds>3600)
        throw std::invalid_argument("CLOUD_INVALID_SESSION");
    std::lock_guard<std::mutex> guard(mutex_);
    clearLocked();
    bearer_=bearer;
    deadline_=now+std::chrono::seconds(ttlSeconds);
    actionIntegrity_=actionIntegrity;
}
std::string SessionCache::get(Clock::time_point now) {
    std::lock_guard<std::mutex> guard(mutex_);
    if(bearer_.empty())return {};
    if(deadline_<=now+std::chrono::seconds(30)) {
        clearLocked();
        return {};
    }
    return bearer_;
}
bool SessionCache::requiresActionIntegrityFor(const std::string& bearer) const {
    std::lock_guard<std::mutex> guard(mutex_);
    // Never apply a newer session's relaxed policy to an old bearer token.
    if(bearer.empty() || bearer!=bearer_ ||
       deadline_<=Clock::now()+std::chrono::seconds(30))return true;
    return actionIntegrity_;
}
void SessionCache::configureAction(const std::string& bearer,std::int64_t project,bool inlineMode) {
    std::lock_guard<std::mutex> guard(mutex_);
    if(bearer.empty()||bearer!=bearer_)return;
    inlineAction_=inlineMode&&project>0;
    actionProject_=inlineAction_?project:0;
}
std::int64_t SessionCache::inlineActionProject(const std::string& bearer) const {
    std::lock_guard<std::mutex> guard(mutex_);
    if(bearer.empty()||bearer!=bearer_||!inlineAction_||
       deadline_<=Clock::now()+std::chrono::seconds(30))return 0;
    return actionProject_;
}
void SessionCache::clear() {
    std::lock_guard<std::mutex> guard(mutex_);
    clearLocked();
}
void SessionCache::clearIfMatches(const std::string& bearer) {
    std::lock_guard<std::mutex> guard(mutex_);
    if(!bearer.empty() && bearer==bearer_)clearLocked();
}
SessionCache& sharedSession() {
    static SessionCache session;
    return session;
}
} // namespace spdecode
