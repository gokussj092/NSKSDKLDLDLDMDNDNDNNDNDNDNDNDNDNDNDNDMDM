#include "spdecode_dark_tunnel.h"
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace spdecode::offline {
namespace {
using Bytes=std::vector<unsigned char>;
using json=nlohmann::json;
struct DarkFailure:std::runtime_error {using std::runtime_error::runtime_error;};
constexpr size_t kMaxEncoded=4u*1024u*1024u;
constexpr size_t kMaxClear=12u*1024u*1024u;
constexpr size_t kMaxDepth=32;
constexpr std::array<unsigned char,16> kIv={
    0x23,0x2e,0x39,0x18,0x55,0x23,0x18,0x4a,
    0x57,0x23,0x58,0x62,0x42,0x20,0x0e,0x05
};
constexpr char kOuterKey[]="$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd";
constexpr char kInnerKey[]="F)J@NcRfUjXn2r4u7x!A%D*G";

void require(bool valid,const char* reason){
    if(!valid)throw DarkFailure(reason);
}
std::string trim(const std::string& value){
    const auto first=value.find_first_not_of(" \r\n\t");
    if(first==std::string::npos)return {};
    const auto last=value.find_last_not_of(" \r\n\t");
    return value.substr(first,last-first+1);
}
bool begins(const std::string& input,const char* expected){
    return input.rfind(expected,0)==0;
}
std::string unwrap(const Bytes& input){
    require(!input.empty()&&input.size()<=kMaxEncoded,"DARK_INVALID_INPUT_SIZE");
    std::string text(input.begin(),input.end());
    text=trim(text);
    require(!text.empty(),"DARK_EMPTY_INPUT");
    const auto marker=text.find("://");
    if(marker!=std::string::npos){
        std::string scheme=text.substr(0,marker);
        std::transform(scheme.begin(),scheme.end(),scheme.begin(),
            [](unsigned char c){return static_cast<char>(std::tolower(c));});
        require(scheme=="dt"||scheme=="dtunnel"||scheme=="dark"||
            scheme=="darktunnel"||scheme=="dark-tunnel","DARK_INVALID_SCHEME");
        text=trim(text.substr(marker+3));
    }
    require(!text.empty()&&text.size()<=kMaxEncoded,"DARK_INVALID_INPUT_SIZE");
    return text;
}
Bytes darkB64(std::string text){
    require(!text.empty()&&text.size()<=kMaxEncoded,"DARK_INVALID_BASE64");
    std::string encoded;encoded.reserve(text.size()+4);
    bool finished=false;
    for(size_t i=0;i<text.size();++i){
        const unsigned char c=static_cast<unsigned char>(text[i]);
        if(c==' '||c=='\t'||c=='\r'||c=='\n'||c=='\v'||c=='\f')continue;
        if(c=='-'||c=='_'){
            require(!finished,"DARK_INVALID_BASE64");
            encoded.push_back(c=='-'?'+':'/');
        }else if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
                 (c>='0'&&c<='9')||c=='+'||c=='/'){
            require(!finished,"DARK_INVALID_BASE64");
            encoded.push_back(static_cast<char>(c));
        }else if(c=='='){
            finished=true;encoded.push_back('=');
        }else{
            throw DarkFailure("DARK_INVALID_BASE64");
        }
    }
    require(encoded.size()>=4 && encoded.size()%4!=1,"DARK_INVALID_BASE64");
    require(encoded.find('=')==std::string::npos||
        (encoded.size()-encoded.find('='))<=2,"DARK_INVALID_BASE64");
    encoded.append((4-encoded.size()%4)%4,'=');
    Bytes result(encoded.size()*3/4+4);
    size_t count=0;
    const int rc=mbedtls_base64_decode(result.data(),result.size(),&count,
        reinterpret_cast<const unsigned char*>(encoded.data()),encoded.size());
    require(rc==0 && count>0 && count<=kMaxEncoded,"DARK_INVALID_BASE64");
    result.resize(count);
    return result;
}
Bytes decryptCfb(const Bytes& encrypted,const char* key,size_t keyBytes){
    require(!encrypted.empty()&&encrypted.size()<=kMaxEncoded,"DARK_INVALID_CFB_SIZE");
    require(keyBytes==24||keyBytes==32,"DARK_INVALID_KEY");
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    std::array<unsigned char,16> iv=kIv;
    size_t offset=0;
    Bytes output(encrypted.size());
    int rc=mbedtls_aes_setkey_enc(&aes,
        reinterpret_cast<const unsigned char*>(key),
        static_cast<unsigned int>(keyBytes*8));
    if(rc==0)rc=mbedtls_aes_crypt_cfb128(&aes,MBEDTLS_AES_DECRYPT,
        encrypted.size(),&offset,iv.data(),encrypted.data(),output.data());
    mbedtls_aes_free(&aes);
    require(rc==0,"DARK_AES_CFB_FAILED");
    return output;
}
bool validUtf8(const Bytes& bytes){
    size_t i=0;
    while(i<bytes.size()){
        const uint8_t c=bytes[i];
        if(c<=0x7f){++i;continue;}
        int remaining=0;
        uint32_t v=0;
        uint32_t min=0;
        if(c>=0xc2&&c<=0xdf){remaining=1;v=c&31;min=128;}
        else if(c>=0xe0&&c<=0xef){remaining=2;v=c&15;min=2048;}
        else if(c>=0xf0&&c<=0xf4){remaining=3;v=c&7;min=65536;}
        else return false;
        if(i+static_cast<size_t>(remaining)>=bytes.size())return false;
        for(int k=0;k<remaining;++k){
            const uint8_t next=bytes[i+1+k];
            if((next&0xc0)!=0x80)return false;
            v=(v<<6)|(next&63);
        }
        if(v<min||v>0x10ffff||(v>=0xd800&&v<=0xdfff))return false;
        i+=static_cast<size_t>(remaining)+1;
    }
    return true;
}
json binaryAsJson(const json& binary){
    const auto& source=binary.get_binary();
    Bytes bytes(source.begin(),source.end());
    if(!bytes.empty()&&validUtf8(bytes)){
        bool printable=true;
        for(unsigned char c:bytes)
            if((c<32&&c!=9&&c!=10&&c!=13)||c==127){printable=false;break;}
        if(printable)return std::string(bytes.begin(),bytes.end());
    }
    json list=json::array();
    for(unsigned char c:bytes)list.push_back(static_cast<unsigned int>(c));
    return list;
}
json decodeMsgpack(const Bytes& data){
    require(!data.empty()&&data.size()<=kMaxEncoded,"DARK_INVALID_MSGPACK_SIZE");
    try {
        auto result=json::from_msgpack(data,true,true);
        require(result.is_object()||result.is_array(),"DARK_INVALID_MSGPACK_ROOT");
        return result;
    }catch(const json::exception&){
        throw DarkFailure("DARK_INVALID_MSGPACK");
    }
}
json normalize(const json& current,int depth,bool insideNested){
    require(depth<=static_cast<int>(kMaxDepth),"DARK_DEPTH_LIMIT");
    if(current.is_binary())return binaryAsJson(current);
    if(current.is_array()){
        require(current.size()<=100000,"DARK_ARRAY_LIMIT");
        json result=json::array();
        for(const auto& value:current)result.push_back(normalize(value,depth+1,insideNested));
        return result;
    }
    if(current.is_object()){
        require(current.size()<=100000,"DARK_OBJECT_LIMIT");
        json result=json::object();
        for(auto it=current.begin();it!=current.end();++it){
            const auto& name=it.key();
            if(name=="Password")continue;
            if(insideNested&&begins(name,"Encrypted")&&it.value().is_binary()){
                const auto& wrapped=it.value().get_binary();
                if(!wrapped.empty()){
                    const Bytes data(wrapped.begin(),wrapped.end());
                    result[name]=normalize(
                        json::binary(decryptCfb(data,kInnerKey,24)),depth+1,true);
                    continue;
                }
            }
            result[name]=normalize(it.value(),depth+1,insideNested);
        }
        return result;
    }
    return current;
}
} // namespace

std::string decodeDarkTunnel(const Bytes& source){
    const std::string encoded=unwrap(source);
    json envelope;
    try {
        if(!encoded.empty()&&encoded[0]=='{')envelope=json::parse(encoded);
        else{
            const Bytes outer=darkB64(encoded);
            envelope=json::parse(outer);
        }
    }catch(const json::exception&){
        throw DarkFailure("DARK_INVALID_JSON_ENVELOPE");
    }
    require(envelope.is_object(),"DARK_INVALID_JSON_ENVELOPE");
    const auto config=envelope.find("encryptedLockedConfig");
    if(config!=envelope.end()&&config->is_string()&&!config->get<std::string>().empty()){
        const auto payload=darkB64(config->get<std::string>());
        const Bytes clear=decryptCfb(payload,kOuterKey,32);
        json result=decodeMsgpack(clear);
        if(result.is_object()){
            auto nested=result.find("EncryptedLockedConfig");
            if(nested!=result.end()&&nested->is_binary()){
                const auto& bytes=nested->get_binary();
                const Bytes innerEncrypted(bytes.begin(),bytes.end());
                if(!innerEncrypted.empty()){
                    const Bytes innerClear=decryptCfb(innerEncrypted,kInnerKey,24);
                    *nested=normalize(decodeMsgpack(innerClear),0,true);
                }
            }
        }
        envelope["encryptedLockedConfig"]=normalize(result,0,false);
    }else if(config!=envelope.end()&&!(config->is_null()||
        (config->is_string()&&config->get<std::string>().empty()))){
        throw DarkFailure("DARK_UNSUPPORTED_PROTECTION");
    }
    // Modern open Dark envelopes have no encryptedLockedConfig and must
    // retain all their original settings, without fake/empty decoded nodes.
    const json finalDoc=normalize(envelope,0,false);
    const std::string serialized=finalDoc.dump(2,' ',false,json::error_handler_t::strict);
    require(!serialized.empty()&&serialized.size()<=kMaxClear,"DARK_OUTPUT_TOO_LARGE");
    return serialized;
}
} // namespace spdecode::offline
