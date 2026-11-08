#include "spdecode_npv_text.h"
#include "spdecode_npv_signed.h"
#include "spdecode_npv_crypto.h"
#include <mbedtls/base64.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>
#include <vector>

namespace spdecode::offline {
namespace {
using Bytes=std::vector<unsigned char>;
using json=nlohmann::json;
constexpr size_t kMax=2u*1024u*1024u;
struct Error:std::runtime_error{using std::runtime_error::runtime_error;};
void require(bool ok,const char* code){if(!ok)throw Error(code);}
std::string s(const Bytes& b){return std::string(b.begin(),b.end());}
bool asciiSpace(char c){return c==' '||c=='\n'||c=='\r'||c=='\t';}
void trim(std::string& str){
    size_t a=0,b=str.size();
    while(a<b&&asciiSpace(str[a]))a++;
    while(b>a&&asciiSpace(str[b-1]))b--;
    str=str.substr(a,b-a);
}
const char* prefixes[]={"npvt://","npvt-ssh://","npvt-vless://","npvt-vmess://","npv://"};
std::string label(const std::string& text){
    for(const auto* prefix:prefixes){
        const size_t n=std::char_traits<char>::length(prefix);
        if(text.size()<=n)continue;
        bool match=true;
        for(size_t i=0;i<n;i++)
            if(std::tolower(static_cast<unsigned char>(text[i]))!=prefix[i])match=false;
        if(match)return prefix;
    }
    return {};
}
Bytes base64(std::string enc){
    enc.erase(std::remove_if(enc.begin(),enc.end(),asciiSpace),enc.end());
    require(!enc.empty()&&enc.size()<=kMax,"NPV_INVALID_BASE64");
    std::string normalized=enc;
    for(char& c:normalized){
        if(c=='-')c='+';
        else if(c=='_')c='/';
        require((c>='A'&&c<='Z')||(c>='a'&&c<='z')||
                (c>='0'&&c<='9')||c=='+'||c=='/'||c=='=',"NPV_INVALID_BASE64");
    }
    const size_t padding=normalized.find('=');
    if(padding!=std::string::npos)
        require(padding>=normalized.size()-2&&normalized.size()%4==0&&
                std::all_of(normalized.begin()+padding,normalized.end(),
                            [](char c){return c=='=';}),"NPV_INVALID_BASE64");
    normalized.append((4-normalized.size()%4)%4,'=');
    Bytes value(normalized.size()*3/4+8);size_t length=0;
    require(mbedtls_base64_decode(value.data(),value.size(),&length,
        reinterpret_cast<const unsigned char*>(normalized.data()),normalized.size())==0,
        "NPV_INVALID_BASE64");
    value.resize(length);
    // Canonical Base64 rejects altered unused padding bits.
    Bytes encoded((value.size()+2)/3*4+8);size_t out=0;
    require(mbedtls_base64_encode(encoded.data(),encoded.size(),&out,
                                 value.data(),value.size())==0,"NPV_INVALID_BASE64");
    std::string check(reinterpret_cast<const char*>(encoded.data()),out);
    while(!check.empty()&&check.back()=='=')check.pop_back();
    auto noPad=normalized;
    while(!noPad.empty()&&noPad.back()=='=')noPad.pop_back();
    require(check==noPad,"NPV_INVALID_BASE64");
    return value;
}
json parse(const Bytes& b){
    return npv::parse(b); // Reject duplicate members as the server does.
}
void embedded(json& node,int depth){
    require(depth<=64,"NPV_NESTING_LIMIT");
    if(node.is_object()){
        for(auto it=node.begin();it!=node.end();++it)embedded(it.value(),depth+1);
    }else if(node.is_array()){
        for(auto& value:node)embedded(value,depth+1);
    }else if(node.is_string()){
        std::string str=node.get<std::string>();
        if(str.rfind("npvs1:",0)!=0)return;
        std::string enc=str.substr(6);
        auto raw=base64(enc);
        auto text=s(raw);
        if(text.rfind("npvs1:",0)==0){node=text;embedded(node,depth+1);return;}
        size_t p=0;while(p<text.size()&&asciiSpace(text[p]))p++;
        if(p<text.size()&&(text[p]=='{'||text[p]=='[')){
            try{
                auto value=npv::parse(raw);
                node=std::move(value);embedded(node,depth+1);return;
            }catch(const npv::Error&){/* Preserve brace-prefixed prose. */}
        }
        // Require valid UTF-8 even when decoded value is an opaque string.
        try{node=json(text);(void)node.dump(-1,' ',false,json::error_handler_t::strict);}
        catch(...){throw Error("NPV_INVALID_UTF8");}
    }
}
}
bool isNpvText(const std::vector<unsigned char>& data){
    if(data.empty()||data.size()>kMax*4)return false;
    auto value=s(data);trim(value);
    return !label(value).empty();
}
std::string decodeNpvText(const std::vector<unsigned char>& data,
                          const std::string& password,const std::string& recipient){
    require(isNpvText(data),"NPV_UNSUPPORTED_TEXT_FORMAT");
    auto value=s(data);trim(value);
    const auto prefix=label(value);
    const auto raw=base64(value.substr(prefix.size()));
    require(raw.size()<=kMax,"NPV_INVALID_INPUT");
    // Signed binary NPVS envelopes must dispatch to their separately
    // authenticated C++ codec; never parse them as plaintext.
    if(raw.size()>=4&&std::equal(raw.begin(),raw.begin()+4,"NPVS"))
        return decodeNpvSigned(raw,password,recipient);
    require(password.empty()&&recipient.empty(),"NPV_CREDENTIALS_NOT_ALLOWED");
    size_t p=0;while(p<raw.size()&&asciiSpace(static_cast<char>(raw[p])))p++;
    require(p<raw.size()&&(raw[p]=='{'||raw[p]=='['),"NPV_UNSUPPORTED_TEXT_PAYLOAD");
    json document=parse(raw);
    require(document.is_object()||document.is_array(),"NPV_INVALID_JSON");
    embedded(document,0);
    return document.dump(2,' ',false,json::error_handler_t::strict)+"\n";
}
} // namespace spdecode::offline
