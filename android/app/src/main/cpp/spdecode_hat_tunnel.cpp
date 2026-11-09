#include "spdecode_hat_tunnel.h"
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>
namespace spdecode::offline {
namespace {
using Bytes=std::vector<unsigned char>;
using json=nlohmann::json;
struct HatError:std::runtime_error {using std::runtime_error::runtime_error;};
constexpr size_t kMaxHatInput=4*1024*1024;
constexpr std::array<unsigned char,16> HAT_KEY={
    205,179,100,184,208,134,72,184,175,164,75,158,167,112,92,52
};
constexpr char XOR_PASSWORD[]="**rVg7EkL~c2" "\x60" "D[aNn";
void check(bool condition,const char* code){if(!condition)throw HatError(code);}
Bytes fromB64(const std::string& text){
    check(!text.empty()&&text.size()<=kMaxHatInput,"HAT_INVALID_SIZE");
    std::string input;
    input.reserve(text.size()+4);
    bool padding=false;
    for(unsigned char ch:text){
        if(ch==' '||ch=='\r'||ch=='\n'||ch=='\t')continue;
        if(ch=='-'||ch=='_'){
            check(!padding,"HAT_INVALID_BASE64");input.push_back(ch=='-'?'+':'/');
        }else if((ch>='A'&&ch<='Z')||(ch>='a'&&ch<='z')||
            (ch>='0'&&ch<='9')||ch=='+'||ch=='/'){
            check(!padding,"HAT_INVALID_BASE64");input.push_back(static_cast<char>(ch));
        }else if(ch=='='){padding=true;input.push_back('=');}
        else throw HatError("HAT_INVALID_BASE64");
    }
    check(input.size()>=4&&input.size()%4!=1,"HAT_INVALID_BASE64");
    if(input.find('=')!=std::string::npos)
        check(input.size()-input.find('=')<=2,"HAT_INVALID_BASE64");
    input.append((4-input.size()%4)%4,'=');
    Bytes out(input.size()*3/4+4);
    size_t count=0;
    const int status=mbedtls_base64_decode(out.data(),out.size(),&count,
        reinterpret_cast<const unsigned char*>(input.data()),input.size());
    check(status==0&&count>0&&count<=kMaxHatInput,"HAT_INVALID_BASE64");
    out.resize(count);
    return out;
}
std::string xorField(const std::string& field){
    const Bytes bytes=fromB64(field);
    std::string output;
    output.reserve(bytes.size());
    for(size_t i=0;i<bytes.size();++i)
        output.push_back(static_cast<char>(bytes[i]^static_cast<unsigned char>(
            XOR_PASSWORD[i%(sizeof(XOR_PASSWORD)-1)])));
    return output;
}
void addV5Fields(json& document){
    auto it=document.find("profilev5");
    if(it==document.end()||!it->is_object())return;
    json expanded=json::object();
    for(const char* name:{"connection_mode","custom_payload","custom_sni","custom_host"}){
        auto value=it->find(name);
        if(value!=it->end()&&value->is_string()&&!value->get<std::string>().empty()){
            try {expanded[name]=xorField(value->get<std::string>());}
            catch(const HatError&){throw HatError("HAT_PROFILE_V5_UNSUPPORTED");}
        }
    }
    if(!expanded.empty())document["decodedProfileV5"]=std::move(expanded);
}
}
std::string decodeHatTunnel(const Bytes& source){
    check(!source.empty()&&source.size()<=kMaxHatInput,"HAT_INVALID_SIZE");
    const Bytes encrypted=fromB64(std::string(source.begin(),source.end()));
    check(encrypted.size()>=16&&encrypted.size()%16==0,"HAT_INVALID_BLOCKS");
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    int rc=mbedtls_aes_setkey_dec(&ctx,HAT_KEY.data(),128);
    Bytes clear(encrypted.size());
    for(size_t i=0;rc==0&&i<encrypted.size();i+=16)
        rc=mbedtls_aes_crypt_ecb(&ctx,MBEDTLS_AES_DECRYPT,
            encrypted.data()+i,clear.data()+i);
    mbedtls_aes_free(&ctx);
    check(rc==0,"HAT_DECRYPTION_FAILED");
    const unsigned char pad=clear.back();
    check(pad>=1&&pad<=16&&pad<=clear.size(),"HAT_UNSUPPORTED_VERSION");
    unsigned char diff=0;
    for(size_t j=0;j<pad;++j)diff|=static_cast<unsigned char>(clear[clear.size()-1-j]^pad);
    check(diff==0,"HAT_UNSUPPORTED_VERSION");
    clear.resize(clear.size()-pad);
    json document;
    try{
        document=json::parse(clear);
    }catch(const json::exception&){
        throw HatError("HAT_UNSUPPORTED_VERSION");
    }
    check(document.is_object(),"HAT_INVALID_DOCUMENT");
    check(document.contains("profile")||document.contains("profilev4")||
        document.contains("profilev5")||document.contains("configuration")||
        document.contains("protextras"),"HAT_UNRECOGNIZED_DOCUMENT");
    addV5Fields(document);
    const std::string result=document.dump(2,' ',false,json::error_handler_t::strict);
    check(result.size()<=12*1024*1024,"HAT_OUTPUT_TOO_LARGE");
    std::fill(clear.begin(),clear.end(),0);
    return result;
}
}
