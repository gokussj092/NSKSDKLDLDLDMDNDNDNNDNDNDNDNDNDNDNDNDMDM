#include "spdecode_keystore_policy.h"
#include <algorithm>
#include <cctype>
#include <limits>

namespace spdecode {
namespace {
constexpr const char* kOld="spdecode.transport.v2";
constexpr const char* kPrefix="spdecode.transport.v3.";
bool urlChar(unsigned char c) {
    return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||
           (c>='0'&&c<='9')||c=='-'||c=='_';
}
} // namespace
bool managedKeystoreAlias(const std::string& alias) {
    return alias==kOld || (alias.size()>std::char_traits<char>::length(kPrefix) &&
        alias.compare(0,std::char_traits<char>::length(kPrefix),kPrefix)==0);
}
std::vector<std::string> managedKeystoreAliases(const std::vector<std::string>& all){
    std::vector<std::string> result;
    for(const auto& alias:all)if(managedKeystoreAlias(alias))result.push_back(alias);
    return result;
}
std::string preferredKeystoreAlias(const std::vector<std::string>& aliases) {
    std::string newest;
    for(const auto& alias:aliases){
        if(alias.compare(0,std::char_traits<char>::length(kPrefix),kPrefix)==0 &&
           alias>newest)newest=alias;
    }
    if(!newest.empty())return newest;
    return std::find(aliases.begin(),aliases.end(),kOld)!=aliases.end()?kOld:"";
}
bool shouldPurgeKeystoreAlias(const std::string& alias,const std::string& active,
                             std::int64_t now) {
    if(alias==active || now<=0 || alias.compare(0,std::char_traits<char>::length(kPrefix),kPrefix)!=0)
        return false;
    const auto start=std::char_traits<char>::length(kPrefix);
    const auto dot=alias.find('.',start);
    if(dot==std::string::npos||dot==start)return false;
    std::int64_t created=0;
    for(std::size_t i=start;i<dot;++i){
        const unsigned char c=static_cast<unsigned char>(alias[i]);
        if(c<'0'||c>'9'||created>(std::numeric_limits<std::int64_t>::max()-9)/10)
            return false;
        created=created*10+(c-'0');
    }
    return created<=now && now-created>600000;
}
bool validEnrollmentChallenge(const std::string& challenge,const std::string& level){
    if(challenge.size()!=43 || (level!="tee" && level!="strongbox"))return false;
    return std::all_of(challenge.begin(),challenge.end(),urlChar);
}
bool validKeyClaim(const std::string& key) {
    return key.size()>=120 && key.size()<=128 &&
        std::all_of(key.begin(),key.end(),urlChar);
}
} // namespace spdecode
