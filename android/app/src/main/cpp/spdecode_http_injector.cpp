#include "spdecode_http_injector.h"
#include <argon2.h>
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/sha256.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace spdecode::offline {
namespace {
using Bytes=std::vector<unsigned char>;
using json=nlohmann::json;
constexpr size_t maxBytes=4u*1024u*1024u;
struct DecodeError:std::runtime_error{using std::runtime_error::runtime_error;};
void check(bool ok,const char* why){if(!ok)throw DecodeError(why);}
Bytes bytes(const std::string& s){return Bytes(s.begin(),s.end());}
std::string text(const Bytes& b){return std::string(b.begin(),b.end());}
constexpr char custom[]="RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs";
constexpr char standard[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr const char* ivs[]={
"221d572349555f1d112133236b1f4a3f",
"5543494c53443e3f4a6a4539384e776a",
"374c2541575e4d531a3c327b75431e5f",
"2c5d1147bbad422b3b334d4d235f1a53",
"522b01433a5e8b2fc7549e1ad368e541",
"337a1035aaedf3458ca167e92d74b839"
};
constexpr char l1[]="7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c";
constexpr char l2[]="b2bc617c32d8b9eb1943a5ffa8051eea";
const Bytes xxKey=Bytes({'n','u','l','l','=','V','5','k','U','5','+','F','F','r','Y',0});
int nib(unsigned char c){
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    if(c>='A'&&c<='F')return c-'A'+10;
    return -1;
}
Bytes hex(const std::string& s){
    check(s.size()%2==0&&s.size()<=maxBytes*2,"EHI_HEX_LENGTH");
    Bytes value;value.reserve(s.size()/2);
    for(size_t i=0;i<s.size();i+=2){
        int a=nib(static_cast<unsigned char>(s[i]));
        int b=nib(static_cast<unsigned char>(s[i+1]));
        check(a>=0&&b>=0,"EHI_INVALID_HEX");
        value.push_back(static_cast<unsigned char>((a<<4)|b));
    }
    return value;
}
Bytes b64(std::string source,bool permissive=false){
    check(source.size()<=maxBytes*2,"EHI_B64_SIZE");
    if(permissive)source.erase(std::remove_if(source.begin(),source.end(),[](unsigned char c){
        return c=='\r'||c=='\n'||c==' '||c=='\t';}),source.end());
    source.append((4-source.size()%4)%4,'=');
    Bytes result(source.size()*3/4+4);size_t length=0;
    check(mbedtls_base64_decode(result.data(),result.size(),&length,
        reinterpret_cast<const unsigned char*>(source.data()),source.size())==0,"EHI_BAD_BASE64");
    result.resize(length);return result;
}
Bytes sha(const Bytes& raw){
    Bytes result(32);
    check(mbedtls_sha256(raw.data(),raw.size(),result.data(),0)==0,"EHI_SHA_FAILED");
    return result;
}
Bytes unpad(Bytes v){
    check(!v.empty()&&v.size()%16==0,"EHI_BAD_PADDING");
    size_t size=v.back();
    check(size>=1&&size<=16&&size<=v.size(),"EHI_BAD_PADDING");
    unsigned char mismatch=0;
    for(size_t i=0;i<size;i++)mismatch|=static_cast<unsigned char>(v[v.size()-1-i]^size);
    check(mismatch==0,"EHI_BAD_PADDING");
    v.resize(v.size()-size);return v;
}
Bytes aesCBC(const Bytes& cipher,const Bytes& key,const Bytes& iv){
    check(!cipher.empty()&&cipher.size()%16==0&&cipher.size()<=maxBytes&&
          (key.size()==16||key.size()==24||key.size()==32)&&iv.size()==16,"EHI_BAD_CBC");
    mbedtls_aes_context aes;mbedtls_aes_init(&aes);
    int rc=mbedtls_aes_setkey_dec(&aes,key.data(),static_cast<unsigned>(key.size()*8));
    Bytes result(cipher.size());
    auto nonce=iv;
    if(rc==0)rc=mbedtls_aes_crypt_cbc(&aes,MBEDTLS_AES_DECRYPT,cipher.size(),
                                     nonce.data(),cipher.data(),result.data());
    mbedtls_aes_free(&aes);
    check(rc==0,"EHI_CBC_FAILED");
    return unpad(std::move(result));
}
uint32_t little(const unsigned char* p){
    return static_cast<uint32_t>(p[0])|(static_cast<uint32_t>(p[1])<<8)|
           (static_cast<uint32_t>(p[2])<<16)|(static_cast<uint32_t>(p[3])<<24);
}
Bytes xxtea(Bytes encrypted){
    if(encrypted.empty())return {};
    while(encrypted.size()%4)encrypted.push_back(0);
    const size_t n=encrypted.size()/4;
    check(n>=2&&n<maxBytes/4,"EHI_XXTEA_BOUNDS");
    std::array<uint32_t,4> key{};
    for(size_t i=0;i<4;i++)key[i]=little(xxKey.data()+4*i);
    std::vector<uint32_t> v(n);
    for(size_t i=0;i<n;i++)v[i]=little(encrypted.data()+4*i);
    const uint32_t delta=0x9e3779b9u;
    uint32_t sum=static_cast<uint32_t>((6+52/n)*delta);
    uint32_t y=v[0];
    while(sum){
        const uint32_t e=(sum>>2)&3u;
        for(size_t p=n-1;p>0;p--){
            const uint32_t z=v[p-1];
            const uint32_t mx=((((z>>5)^(y<<2))+((y>>3)^(z<<4)))^
                               ((sum^y)+(key[(p&3u)^e]^z)));
            y=v[p]=v[p]-mx;
        }
        const uint32_t z=v[n-1];
        const uint32_t mx=((((z>>5)^(y<<2))+((y>>3)^(z<<4)))^
                           ((sum^y)+(key[e]^z)));
        y=v[0]=v[0]-mx;
        sum-=delta;
    }
    Bytes result(n*4);
    for(size_t i=0;i<n;i++){
        for(int j=0;j<4;j++)result[4*i+j]=static_cast<unsigned char>(v[i]>>(8*j));
    }
    // The server's XXTEA data contract takes v[-1] as payload byte length.
    if(v[n-1]>0&&v[n-1]<=result.size())result.resize(v[n-1]);
    else while(!result.empty()&&result.back()==0)result.pop_back();
    return result;
}
size_t parseUTF(const Bytes& data,size_t offset){
    check(offset+2<=data.size(),"EHI_TRUNCATED_HEADER");
    size_t length=(static_cast<size_t>(data[offset])<<8)|data[offset+1];
    check(length<=4096&&offset+2+length<=data.size(),"EHI_INVALID_HEADER");
    return offset+2+length;
}
Bytes outerPayload(const Bytes& raw){
    auto offset=parseUTF(raw,0);
    check(offset+8<=raw.size(),"EHI_TRUNCATED");
    offset+=8;offset=parseUTF(raw,offset);
    check(offset+12<=raw.size(),"EHI_TRUNCATED");
    offset+=8;
    size_t length=(static_cast<size_t>(raw[offset])<<24)|
        (static_cast<size_t>(raw[offset+1])<<16)|
        (static_cast<size_t>(raw[offset+2])<<8)|raw[offset+3];
    offset+=12;
    check(length>0&&length<=maxBytes&&offset+length==raw.size(),"EHI_BAD_PAYLOAD");
    return Bytes(raw.begin()+offset,raw.begin()+offset+length);
}
std::string xorLayer(const std::string& source,const std::string& key){
    check(!key.empty(),"EHI_NO_SALT");
    std::string reversed;
    reversed.reserve(source.size());
    for(auto it=source.rbegin();it!=source.rend();++it)
        if(*it!='?')reversed.push_back(*it);
    for(char& c:reversed){
        const auto pos=std::string(custom).find(c);
        if(pos!=std::string::npos)c=standard[pos];
    }
    Bytes hexText=b64(reversed);
    std::string original= text(hexText);
    if(original.size()%2)original.insert(original.begin(),'0');
    const Bytes raw=hex(original);
    Bytes clear;clear.reserve(raw.size());
    for(size_t i=0;i<raw.size();i++){
        unsigned char v=static_cast<unsigned char>(raw[i]^key[i%key.size()]);
        if(v)clear.push_back(v);
    }
    // Reject obvious mis-decodes; otherwise preserve the entire string.
    if(clear.empty())return "";
    size_t control=0;
    for(auto c:clear)if(c<32&&c!='\t'&&c!='\n'&&c!='\r')control++;
    check(static_cast<double>(control)/clear.size()<=0.5,"EHI_BAD_XOR_TEXT");
    return text(clear);
}
std::string pythonStr(const json& v){
    if(v.is_string())return v.get<std::string>();
    if(v.is_boolean())return v.get<bool>()?"True":"False";
    if(v.is_null())return "None";
    return v.dump();
}
std::string scalar(const json& j,const char* key,const std::string& fallback=""){
    if(!j.is_object()||!j.contains(key))return fallback;
    return pythonStr(j[key]);
}
Bytes masterKey(const json& cfg){
    std::string source;
    for(const char* key:{"configAesKey","configIdentifier","configSalt",
                         "configTimestamp","configExpiryTimestamp","lockModes",
                         "lockModesHash","configHwid","configLockMobileOperatorId"}){
        std::string item=scalar(cfg,key,key==std::string("configTimestamp")||
                                            key==std::string("configExpiryTimestamp")?"0":"");
        if(!item.empty())source+=item;
    }
    return sha(bytes(source));
}
uint32_t rotate(uint32_t value,int n){return (value<<n)|(value>>(32-n));}
void quarter(std::array<uint32_t,16>& s,int a,int b,int c,int d){
    s[a]+=s[b];s[d]=rotate(s[d]^s[a],16);
    s[c]+=s[d];s[b]=rotate(s[b]^s[c],12);
    s[a]+=s[b];s[d]=rotate(s[d]^s[a],8);
    s[c]+=s[d];s[b]=rotate(s[b]^s[c],7);
}
void setLE(unsigned char* dst,uint32_t v){
    for(int i=0;i<4;i++)dst[i]=static_cast<unsigned char>((v>>(8*i))&255);
}
Bytes hchacha(const Bytes& key,const Bytes& nonce){
    check(key.size()==32&&nonce.size()==24,"EHI_INVALID_XCHACHA");
    std::array<uint32_t,16> s={};
    s[0]=0x61707865;s[1]=0x3320646e;s[2]=0x79622d32;s[3]=0x6b206574;
    for(int i=0;i<8;i++)s[4+i]=little(key.data()+4*i);
    for(int i=0;i<4;i++)s[12+i]=little(nonce.data()+4*i);
    for(int i=0;i<10;i++){
        quarter(s,0,4,8,12);quarter(s,1,5,9,13);
        quarter(s,2,6,10,14);quarter(s,3,7,11,15);
        quarter(s,0,5,10,15);quarter(s,1,6,11,12);
        quarter(s,2,7,8,13);quarter(s,3,4,9,14);
    }
    Bytes sub(32);
    for(int i=0;i<4;i++)setLE(sub.data()+i*4,s[i]);
    for(int i=0;i<4;i++)setLE(sub.data()+16+i*4,s[i+12]);
    std::fill(s.begin(),s.end(),0);
    return sub;
}
Bytes chacha(const Bytes& ciphertext,const Bytes& tag,const Bytes& key,
             const Bytes& nonce,const Bytes& aad){
    check(key.size()==32&&(nonce.size()==12||nonce.size()==24)&&tag.size()==16,
          "EHI_BAD_AEAD");
    Bytes actualKey=key;
    Bytes actualNonce=nonce;
    if(nonce.size()==24){
        actualKey=hchacha(key,nonce);
        actualNonce=Bytes(12,0);
        std::copy(nonce.begin()+16,nonce.end(),actualNonce.begin()+4);
    }
    mbedtls_chachapoly_context ctx;mbedtls_chachapoly_init(&ctx);
    int rc=mbedtls_chachapoly_setkey(&ctx,actualKey.data());
    Bytes result(ciphertext.size());
    if(rc==0)rc=mbedtls_chachapoly_auth_decrypt(&ctx,ciphertext.size(),actualNonce.data(),
        aad.data(),aad.size(),tag.data(),ciphertext.data(),result.data());
    mbedtls_chachapoly_free(&ctx);check(rc==0,"AUTH_FAILED");return result;
}
std::string configMessage(const std::string& source){
    // The standard EHI message wrapper is UTF-8 Base64 of UTF-16 code
    // units XORed with the constant "EHIMSG". For ASCII the mappings are
    // identical byte-by-byte. Non-ASCII is preserved until a fully validated
    // Unicode conversion is added instead of silently corrupting it.
    try{
        auto raw=b64(source);
        std::string s=text(raw);
        bool ascii=std::all_of(s.begin(),s.end(),[](unsigned char c){return c<128;});
        if(!ascii)return source;
        const std::string key="EHIMSG";
        for(size_t i=0;i<s.size();i++)s[i]=static_cast<char>(s[i]^key[i%key.size()]);
        return s;
    }catch(...){return source;}
}
void recursivelyDecode(json& value,const std::string& name,const std::string& salt,int depth){
    if(depth>32)return;
    if(value.is_object()){
        for(auto it=value.begin();it!=value.end();++it)recursivelyDecode(it.value(),it.key(),salt,depth+1);
    }else if(value.is_array()){
        for(auto& item:value)recursivelyDecode(item,"",salt,depth+1);
    }else if(value.is_string()){
        auto s=value.get<std::string>();
        if(s.empty())return;
        if(name=="configMessage")value=configMessage(s);
        else{
            try{
                auto clear=xorLayer(s,salt);
                if(!clear.empty())value=clear;
            }catch(...){}
        }
    }
}
} // namespace
std::string decodeHttpInjector(const std::vector<unsigned char>& raw){
    check(!raw.empty()&&raw.size()<=maxBytes,"EHI_INVALID_SIZE");
    const Bytes encrypted=outerPayload(raw);
    json cfg;int variant=-1;
    const Bytes key1=hex(l1),key2=hex(l2);
    for(int i=0;i<6;i++){
        try{
            auto outer=text(aesCBC(encrypted,key1,hex(ivs[i])));
            const auto first=outer.find(':');
            if(first==std::string::npos)continue;
            const auto second=outer.find(':',first+1);
            if(second==std::string::npos)continue;
            const auto third=outer.find(':',second+1);
            const auto iv=b64(outer.substr(0,first));
            const auto cipher=b64(outer.substr(second+1,third==std::string::npos?
                                           std::string::npos:third-second-1));
            const auto decoded=xxtea(aesCBC(cipher,key2,iv));
            const auto offset=std::find(decoded.begin(),decoded.end(),'{');
            if(offset==decoded.end())continue;
            auto tentative=json::parse(offset,decoded.end(),nullptr,false);
            if(tentative.is_object()){cfg=std::move(tentative);variant=i;break;}
        }catch(...){}
    }
    check(variant>=0,"EHI_UNRECOGNIZED_FORMAT");
    const auto salt=scalar(cfg,"configSalt","EVZJNI");
    json result=cfg;
    if(variant>=3){
        std::string encoded;
        try{encoded=xorLayer(scalar(cfg,"configData"),salt);}
        catch(...){throw DecodeError("EHI_MISSING_CONFIG_DATA");}
        Bytes protectedPayload=b64(encoded);
        check(protectedPayload.size()>50+16,"EHI_INVALID_STANDARD_PAYLOAD");
        const uint32_t time=little(protectedPayload.data()+1);
        const uint32_t memory=little(protectedPayload.data()+5);
        const uint32_t lanes=protectedPayload[9];
        check(time>=1&&time<=10&&memory>=8&&memory<=256*1024&&lanes>=1&&lanes<=8,
              "EHI_ARGON2_LIMIT");
        Bytes secret=masterKey(cfg),derived(32);
        const int status=argon2id_hash_raw(time,memory,lanes,secret.data(),
            secret.size(),protectedPayload.data()+10,16,derived.data(),32);
        std::fill(secret.begin(),secret.end(),0);
        check(status==ARGON2_OK,"EHI_ARGON2_FAILED");
        const Bytes nonce(protectedPayload.begin()+26,protectedPayload.begin()+50);
        const Bytes ciphertext(protectedPayload.begin()+50,protectedPayload.end()-16);
        const Bytes tag(protectedPayload.end()-16,protectedPayload.end());
        const Bytes aad(protectedPayload.begin(),protectedPayload.begin()+26);
        const Bytes decoded=chacha(ciphertext,tag,derived,nonce,aad);
        std::fill(derived.begin(),derived.end(),0);
        result=json::parse(decoded.begin(),decoded.end());
        check(result.is_object()||result.is_array(),"EHI_INVALID_DOCUMENT");
    }
    recursivelyDecode(result,"",salt,0);
    return result.dump(2,' ',false,json::error_handler_t::strict)+"\n";
}
} // namespace spdecode::offline
