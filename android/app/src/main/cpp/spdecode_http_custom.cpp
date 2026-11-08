#include "spdecode_http_custom.h"
#include <argon2.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/base64.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace spdecode::offline {
namespace {
using json = nlohmann::json;
using Bytes = std::vector<unsigned char>;
constexpr size_t MAX_BYTES = 4u*1024u*1024u;
constexpr char PKG[] = "xyz.easypro.httpcustom";
const std::string OUTER_AAD_4 = std::string("HCX4|")+PKG+"|1";
const std::string OUTER_AAD_OLD = std::string("HCX1|")+PKG+"|1";
const std::string OUTER_SEED_OLD = std::string("hc-envelope-seal-v1 ")+PKG;
constexpr char OUTER_SALT_OLD[]="hc-envelope-seal-salt-v1";
constexpr char OUTER_INFO_OLD[]="hc-envelope-seal-info-v1";
constexpr char OUTER_SALT_4[]="hc-envelope-seal-salt-v4";
constexpr char OUTER_INFO_4[]="hc-envelope-seal-info-v4";
const std::string HEX_V3_KEY="88702df6ae8c089c9478b8cd2bd3f30961b3574a58063d024bdc50f6b779e26f";
const std::string HEX_N7_KEY="9ba7ff3baf33db7aad807a86574b7ca55bef2f048ead51f3a1fe0cff389db3b3";
const std::string HEX_C0="95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181"
                         "38cabb40b2f81a5a30b11a97cbcf0fed755aa8c2b5495e9bc0c1902077a4cd92";
const std::string HEX_CERT="95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181";
const std::array<uint32_t,8> INNER_STATE={
    0x82515a9a,0xf6ec05fc,0xf650b6cd,0x523f8ce6,0xedf419ec,0x1d6d6573,0x66ff1b89,0xf40a0181
};
const std::array<uint32_t,8> OUTER_STATE={
    0x82185b01,0x35cb48be,0xdb6c3846,0xbd714ec5,0x627728af,0xdbaae4db,0x463fbf8d,0x88a24381
};
struct HCError:std::runtime_error {using std::runtime_error::runtime_error;};
void ensure(bool ok,const char* message){if(!ok)throw HCError(message);}
Bytes asBytes(const std::string& value){return Bytes(value.begin(),value.end());}
std::string asString(const Bytes& value){return std::string(value.begin(),value.end());}
void add(Bytes& dst,const Bytes& v){dst.insert(dst.end(),v.begin(),v.end());}
void add(Bytes& dst,const std::string& v){dst.insert(dst.end(),v.begin(),v.end());}
void addNull(Bytes& dst){dst.push_back(0);}
Bytes fromHex(const std::string& encoded){
    ensure(encoded.size()%2==0&&encoded.size()<=MAX_BYTES*2,"HC_INVALID_HEX");
    auto nibble=[](unsigned char c)->int {
        if(c>='0'&&c<='9')return c-'0';
        if(c>='a'&&c<='f')return c-'a'+10;
        if(c>='A'&&c<='F')return c-'A'+10;
        return -1;
    };
    Bytes output;output.reserve(encoded.size()/2);
    for(size_t i=0;i<encoded.size();i+=2){
        const int a=nibble(static_cast<unsigned char>(encoded[i]));
        const int b=nibble(static_cast<unsigned char>(encoded[i+1]));
        ensure(a>=0&&b>=0,"HC_INVALID_HEX");
        output.push_back(static_cast<unsigned char>((a<<4)|b));
    }
    return output;
}
Bytes sha(const Bytes& data){
    Bytes out(32);ensure(mbedtls_sha256(data.data(),data.size(),out.data(),0)==0,"HC_SHA256_FAILED");
    return out;
}
Bytes fromState(const std::array<uint32_t,8>& state,const Bytes& input){
    mbedtls_sha256_context ctx;mbedtls_sha256_init(&ctx);
    int rc=mbedtls_sha256_starts(&ctx,0);
    if(rc==0){
        for(size_t i=0;i<8;i++)ctx.MBEDTLS_PRIVATE(state)[i]=state[i];
        ctx.MBEDTLS_PRIVATE(total)[0]=64;
        ctx.MBEDTLS_PRIVATE(total)[1]=0;
        rc=mbedtls_sha256_update(&ctx,input.data(),input.size());
    }
    Bytes output(32);
    if(rc==0)rc=mbedtls_sha256_finish(&ctx,output.data());
    mbedtls_sha256_free(&ctx);
    ensure(rc==0,"HC_FOLD_FAILED");
    return output;
}
Bytes nativeFold(const Bytes& input){
    Bytes transcript={0xe9};add(transcript,fromHex(HEX_CERT));add(transcript,input);
    return fromState(OUTER_STATE,fromState(INNER_STATE,transcript));
}
Bytes mac(const Bytes& key,const Bytes& value){
    auto* md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    ensure(md!=nullptr,"HC_HMAC_UNAVAILABLE");
    Bytes out(32);
    ensure(mbedtls_md_hmac(md,key.data(),key.size(),value.data(),value.size(),out.data())==0,
           "HC_HMAC_FAILED");
    return out;
}
Bytes hkdf(const Bytes& material,const Bytes& salt,const Bytes& info){
    auto* md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    ensure(md!=nullptr,"HC_HKDF_UNAVAILABLE");
    Bytes out(32);
    ensure(mbedtls_hkdf(md,salt.data(),salt.size(),material.data(),material.size(),
                        info.data(),info.size(),out.data(),out.size())==0,"HC_HKDF_FAILED");
    return out;
}
uint32_t rotl(uint32_t x,int bits){return (x<<bits)|(x>>(32-bits));}
void quarter(std::array<uint32_t,16>& s,int a,int b,int c,int d){
    s[a]+=s[b];s[d]=rotl(s[d]^s[a],16);
    s[c]+=s[d];s[b]=rotl(s[b]^s[c],12);
    s[a]+=s[b];s[d]=rotl(s[d]^s[a],8);
    s[c]+=s[d];s[b]=rotl(s[b]^s[c],7);
}
uint32_t readLE(const unsigned char* bytes){
    return static_cast<uint32_t>(bytes[0])|(static_cast<uint32_t>(bytes[1])<<8)|
        (static_cast<uint32_t>(bytes[2])<<16)|(static_cast<uint32_t>(bytes[3])<<24);
}
void writeLE(unsigned char* bytes,uint32_t value){
    for(int i=0;i<4;i++)bytes[i]=static_cast<unsigned char>(value>>(8*i));
}
Bytes hchacha(const Bytes& key,const unsigned char* nonce16){
    ensure(key.size()==32,"HC_BAD_KEY");
    const std::array<uint32_t,4> constant={0x61707865,0x3320646e,0x79622d32,0x6b206574};
    std::array<uint32_t,16> state{};
    for(size_t i=0;i<4;i++)state[i]=constant[i];
    for(size_t i=0;i<8;i++)state[4+i]=readLE(key.data()+i*4);
    for(size_t i=0;i<4;i++)state[12+i]=readLE(nonce16+i*4);
    for(int i=0;i<10;i++){
        quarter(state,0,4,8,12);quarter(state,1,5,9,13);
        quarter(state,2,6,10,14);quarter(state,3,7,11,15);
        quarter(state,0,5,10,15);quarter(state,1,6,11,12);
        quarter(state,2,7,8,13);quarter(state,3,4,9,14);
    }
    Bytes sub(32);
    for(size_t i=0;i<4;i++)writeLE(sub.data()+4*i,state[i]);
    for(size_t i=0;i<4;i++)writeLE(sub.data()+16+4*i,state[i+12]);
    std::fill(state.begin(),state.end(),0);
    return sub;
}
Bytes xdec(const Bytes& key,const Bytes& nonce,const Bytes& aad,const Bytes& sealed){
    ensure(key.size()==32&&nonce.size()==24&&sealed.size()>=16&&sealed.size()<=MAX_BYTES,
           "HC_INVALID_AEAD");
    const Bytes sub=hchacha(key,nonce.data());
    std::array<unsigned char,12> iv{};
    std::copy(nonce.begin()+16,nonce.end(),iv.begin()+4);
    mbedtls_chachapoly_context cipher;mbedtls_chachapoly_init(&cipher);
    int rc=mbedtls_chachapoly_setkey(&cipher,sub.data());
    Bytes out(sealed.size()-16);
    if(rc==0){
        const unsigned char* ptr=sealed.data()+sealed.size()-16;
        rc=mbedtls_chachapoly_auth_decrypt(&cipher,out.size(),iv.data(),
            aad.empty()?nullptr:aad.data(),aad.size(),ptr,sealed.data(),out.data());
    }
    mbedtls_chachapoly_free(&cipher);
    ensure(rc==0,"AUTH_FAILED");
    return out;
}
// Only accepted for historical v3 outer carriers. Never an authenticated result:
// inner sections must still pass their AEAD tags before the result is returned.
Bytes streamV3(const Bytes& key,const Bytes& nonce,const Bytes& encrypted){
    ensure(key.size()==32&&nonce.size()==24,"HC_INVALID_V3");
    const Bytes sub=hchacha(key,nonce.data());
    unsigned char iv[12]={};
    std::copy(nonce.begin()+16,nonce.end(),iv+4);
    Bytes out(encrypted.size());
    ensure(mbedtls_chacha20_crypt(sub.data(),iv,1,encrypted.size(),encrypted.data(),
                                 out.data())==0,"HC_INVALID_V3_STREAM");
    return out;
}
bool latin1Carrier(const Bytes& source,Bytes& dest){
    dest.clear();dest.reserve(source.size());
    for(size_t i=0;i<source.size();){
        unsigned char a=source[i++];
        if(a<128){dest.push_back(a);continue;}
        if(a==0xc2||a==0xc3){
            if(i>=source.size())return false;
            const unsigned char b=source[i++];
            if(b<0x80||b>0xbf)return false;
            dest.push_back(static_cast<unsigned char>(((a&3)<<6)|(b&63)));
            continue;
        }
        return false;
    }
    return dest!=source;
}
std::vector<Bytes> carriers(const Bytes& source){
    std::vector<Bytes> all;
    Bytes value=source;
    for(int i=0;i<6;i++){
        if(value.size()>=40)all.push_back(value);
        Bytes next;if(!latin1Carrier(value,next))break;
        value=std::move(next);
    }
    return all;
}
json jsonFromBytes(const Bytes& bytes){
    try{return json::parse(bytes.begin(),bytes.end());}
    catch(...){throw HCError("HC_INVALID_JSON");}
}
bool tryJson(const Bytes& bytes,json& result){
    try{result=json::parse(bytes.begin(),bytes.end());return true;}catch(...){return false;}
}
std::string str(const json& j,const char* field){
    ensure(j.is_object()&&j.contains(field)&&j.at(field).is_string(),"HC_INVALID_MEMBER");
    return j.at(field).get<std::string>();
}
int64_t integer(const json& j,const char* field){
    ensure(j.is_object()&&j.contains(field)&&j.at(field).is_number_integer(),"HC_INVALID_INTEGER");
    return j.at(field).get<int64_t>();
}
Bytes features(const json& envelope){
    ensure(envelope.contains("f")&&envelope["f"].is_array(),"HC_INVALID_FEATURES");
    std::string joined;
    bool first=true;
    for(const auto& entry:envelope["f"]){
        ensure(entry.is_string(),"HC_INVALID_FEATURES");
        if(!first)joined.push_back(',');
        first=false;
        joined+=entry.get<std::string>();
    }
    return asBytes(joined);
}
std::string hwidNormalized(const std::string& value){
    auto first=value.find_first_not_of(" \r\n\t");
    ensure(first!=std::string::npos,"HC_INVALID_HWID");
    auto last=value.find_last_not_of(" \r\n\t");
    auto out=value.substr(first,last-first+1);
    ensure(out.size()==32,"HC_INVALID_HWID");
    for(char& ch:out){
        ensure((ch>='0'&&ch<='9')||(ch>='a'&&ch<='f')||
               (ch>='A'&&ch<='F')||ch=='h'||ch=='H',"HC_INVALID_HWID");
        ch=static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    return out;
}
Bytes passKdf(const json& envelope,const std::string& password,const Bytes& seed,
              Bytes& protectionAAD){
    ensure(str(envelope,"k")=="ARGON2ID13"||str(envelope,"k")=="a1","HC_BAD_ARGON2_TYPE");
    const int64_t ops=integer(envelope,"l");
    const int64_t memory=integer(envelope,"m");
    ensure(ops>=1&&ops<=10&&memory>=8192&&memory<=256ll*1024*1024&&memory%1024==0,
           "HC_ARGON2_LIMIT");
    ensure(password.size()<=4096&&!password.empty(),"HC_INVALID_PASSWORD");
    Bytes output(32);
    const int status=argon2id_hash_raw(static_cast<uint32_t>(ops),
        static_cast<uint32_t>(memory/1024),1,password.data(),password.size(),
        seed.data(),16,output.data(),output.size());
    ensure(status==ARGON2_OK,"HC_ARGON2_FAILED");
    protectionAAD=asBytes("|1|ARGON2ID13|"+std::to_string(ops)+"|"+std::to_string(memory));
    return output;
}
bool boolFlag(const json& j){
    if(!j.contains("h"))return false;
    const auto& v=j.at("h");
    if(v.is_boolean())return v.get<bool>();
    ensure(v.is_number_integer(),"HC_INVALID_PROTECTION_FLAG");
    const auto n=v.get<int>();
    ensure(n==0||n==1,"HC_INVALID_PROTECTION_FLAG");
    return n==1;
}
struct Material {Bytes key;Bytes aad;};
Material derive(const json& envelope,const std::string& password,const std::string& hwid,
                bool modern){
    ensure(str(envelope,"a")=="HCCFG","HC_INVALID_MAGIC");
    const auto schema=integer(envelope,"b");
    const auto schedule=str(envelope,"e");
    const std::string cipher=str(envelope,"c");
    const std::string kdf=str(envelope,"d");
    if(modern){
        ensure(schema==10&&cipher=="s1"&&kdf=="h1"&&
            (schedule=="n11"||schedule=="n12"),"HC_UNSUPPORTED_SCHEMA");
    }else{
        ensure((schema==1||schema==2||schema==5||schema==7)&&
            (cipher==(schema==1?"XCHACHA20P1305":"s1"))&&
            (kdf==(schema==1?"NATIVE-HKDF-SHA256":"h1"))&&
            (schedule=="n1"||schedule=="n2"||schedule=="n7"||schedule=="n8"),"HC_UNSUPPORTED_SCHEMA");
    }
    const bool lock=modern?(schedule=="n12"):(schedule=="n2"||schedule=="n8");
    const bool n7=!modern&&(schedule=="n7"||schedule=="n8");
    const bool protectedPw=boolFlag(envelope);
    if(lock&&hwid.empty())throw HCError(protectedPw&&password.empty()?
       "HWID_PASSWORD_REQUIRED":"HWID_REQUIRED");
    if(protectedPw&&password.empty())throw HCError("PASSWORD_REQUIRED");
    const auto seed=fromHex(str(envelope,"g"));
    ensure(seed.size()==32,"HC_INVALID_SEED");
    const auto f=features(envelope);
    const bool hasBuild=envelope.contains("n")&&!envelope.at("n").is_null();
    std::string build;
    if(hasBuild){
        ensure(envelope["n"].is_number_unsigned()||
               (envelope["n"].is_number_integer()&&envelope["n"].get<int64_t>()>=0),
               "HC_INVALID_BUILD");
        build=std::to_string(envelope["n"].get<uint64_t>());
    }
    if(modern)ensure(hasBuild,"HC_MISSING_BUILD");
    const std::string device=lock?hwidNormalized(hwid):std::string();
    Bytes transcript=asBytes("HCCFG");
    addNull(transcript);add(transcript,PKG);addNull(transcript);add(transcript,"1");
    addNull(transcript);add(transcript,f);addNull(transcript);
    if(hasBuild){add(transcript,build);addNull(transcript);}
    if(lock){add(transcript,"hwid");addNull(transcript);add(transcript,device);addNull(transcript);}
    add(transcript,seed);
    Bytes ikm;
    if(modern) ikm=nativeFold(transcript);
    else if(n7) {
        Bytes msg={0xd3};
        const Bytes prefix=fromHex(HEX_C0);
        msg.insert(msg.end(),prefix.begin(),prefix.begin()+32);
        add(msg,transcript);
        ikm=mac(fromHex(HEX_N7_KEY),msg);
    }else{
        Bytes message=fromHex(HEX_C0);add(message,transcript);ikm=sha(message);
    }
    Bytes passwordAAD=asBytes("|0");
    if(protectedPw){
        const Bytes pass=passKdf(envelope,password,seed,passwordAAD);
        add(ikm,pass);
    }
    Bytes info=asBytes("app-config|"+schedule+"|"+PKG+"|1|");
    add(info,f);
    if(hasBuild)add(info,"|"+build);
    if(lock)add(info,"|hwid|"+device);
    const Bytes derived=hkdf(ikm,seed,info);
    Bytes aad=asBytes("HCCFG|"+std::to_string(schema)+
        "|XCHACHA20P1305|NATIVE-HKDF-SHA256|"+schedule+"|"+PKG+"|1|");
    add(aad,f);add(aad,passwordAAD);
    if(hasBuild)add(aad,"|"+build);
    if(lock){
        ensure(envelope.contains("o")&&envelope["o"].is_array()&&
               !envelope["o"].empty()&&envelope["o"].size()<=4096,"HC_INVALID_HWID_SLOTS");
        for(const auto& slot:envelope["o"]){
            try {
                auto nonce=fromHex(str(slot,"a"));
                auto sealed=fromHex(str(slot,"b"));
                Bytes slotAAD=aad;addNull(slotAAD);add(slotAAD,"w");
                auto session=xdec(derived,nonce,slotAAD,sealed);
                if(session.size()==32)return {session,aad};
            }catch(const HCError&){}
        }
        throw HCError("AUTH_FAILED");
    }
    return {derived,aad};
}
bool openEnvelope(const Bytes& source,bool modern,json& envelope){
    Bytes key;
    const Bytes first=asBytes(modern?(std::string("hc-envelope-seal-v4 ")+PKG):OUTER_SEED_OLD);
    if(modern)key=hkdf(nativeFold(first),asBytes(OUTER_SALT_4),asBytes(OUTER_INFO_4));
    else {
        Bytes msg=fromHex(HEX_C0);add(msg,first);
        key=hkdf(sha(msg),asBytes(OUTER_SALT_OLD),asBytes(OUTER_INFO_OLD));
    }
    for(const auto& carrier:carriers(source)){
        if(carrier.size()<40)continue;
        Bytes nonce(carrier.begin(),carrier.begin()+24);
        Bytes sealed(carrier.begin()+24,carrier.end());
        try {
            const auto plain=xdec(key,nonce,asBytes(modern?OUTER_AAD_4:OUTER_AAD_OLD),sealed);
            json obj=jsonFromBytes(plain);
            ensure(obj.is_object()&&obj.value("a",std::string())=="HCCFG","HC_INVALID_ENVELOPE");
            envelope=std::move(obj);
            return true;
        }catch(const HCError&){}
        if(modern)continue;
        // Historical v3 envelope had no outer tag. Inner sections still must
        // authenticate, and no untrusted plaintext is returned before that.
        try {
            if(sealed.size()<16)continue;
            sealed.resize(sealed.size()-16);
            json obj=jsonFromBytes(streamV3(fromHex(HEX_V3_KEY),nonce,sealed));
            if(obj.is_object()&&obj.value("a",std::string())=="HCCFG"){
                envelope=std::move(obj);return true;
            }
        }catch(const HCError&){}
    }
    return false;
}
Bytes openSection(const json& section,const Bytes& key,const Bytes& aad){
    const auto label=str(section,"a");
    ensure(!label.empty(),"HC_BAD_SECTION_LABEL");
    const auto nonce=fromHex(str(section,"b"));
    const auto sealed=fromHex(str(section,"c"));
    Bytes sectionAAD=aad;addNull(sectionAAD);add(sectionAAD,label);
    return xdec(key,nonce,sectionAAD,sealed);
}
bool sidecar(const json& section,const Bytes& key,const Bytes& aad,Bytes& output){
    if(!section.contains("d")||section["d"].is_null())return false;
    const auto& nested=section.at("d");
    ensure(nested.is_object(),"HC_BAD_SIDECAR");
    Bytes sectionAAD=aad;addNull(sectionAAD);add(sectionAAD,str(section,"a")+":x");
    output=xdec(key,fromHex(str(nested,"a")),sectionAAD,fromHex(str(nested,"b")));
    return true;
}
class HPC {
    const Bytes& bytes;size_t offset=0;
public:
    explicit HPC(const Bytes& raw):bytes(raw){}
    Bytes take(size_t size){
        ensure(size<=bytes.size()-offset,"HC_TRUNCATED_HPC1");
        Bytes output(bytes.begin()+offset,bytes.begin()+offset+size);
        offset+=size;return output;
    }
    uint32_t u32(){
        auto data=take(4);return (static_cast<uint32_t>(data[0])<<24)|
            (static_cast<uint32_t>(data[1])<<16)|(static_cast<uint32_t>(data[2])<<8)|data[3];
    }
    uint64_t u64(){
        const auto data=take(8);uint64_t v=0;
        for(unsigned char c:data){v=(v<<8)|c;}
        return v;
    }
    std::string text(){
        const size_t len=u32();
        ensure(len<=MAX_BYTES,"HC_HPC1_STRING_TOO_LONG");
        return asString(take(len));
    }
    bool ended()const{return offset==bytes.size();}
};
json profile(const Bytes& plain,const std::string& label,bool modern){
    HPC rd(plain);
    ensure(asString(rd.take(4))=="HPC1"&&rd.u32()==11,"HC_BAD_HPC1");
    json entry;
    entry["name"]=rd.text();entry["protocol"]=rd.text();entry["host"]=rd.text();
    entry["port"]=rd.u32();entry["username"]=rd.text();entry["password"]=rd.text();
    auto payload=rd.text();
    const auto optionsText=rd.text();
    const uint32_t flags=rd.u32();
    const uint64_t updated=rd.u64();
    const auto mode=rd.text();
    ensure(rd.ended(),"HC_HPC1_TRAILING");
    if(modern){
        entry["label"]=label;
        entry["payload"]=payload;
        json options=json::object();
        if(!optionsText.empty()){
            try{options=json::parse(optionsText);}
            catch(...){options=optionsText;}
        }
        entry["options"]=options;
        entry["options_text"]=optionsText;
        entry["flags"]=flags;
        entry["updated_at_ms"]=updated;
        entry["mode"]=mode;
    }else{
        entry["mode"]=mode;
        if(!optionsText.empty()){
            try {
                auto parsed=json::parse(optionsText);
                if(parsed.is_object())for(auto it=parsed.begin();it!=parsed.end();++it)entry[it.key()]=it.value();
            }catch(...){}
        }
        if(!payload.empty())entry["payload"]=payload;
    }
    return entry;
}
json content(const Bytes& raw,bool modern){
    json parsed;
    if(tryJson(raw,parsed))return parsed;
    try {
        // JSON parser validates Unicode encoding when serializing strings.
        const std::string text=asString(raw);
        const auto checked=json(text).dump();
        (void)checked;
        return text;
    }catch(...){
        // Binary sidecars must remain lossless; don't return guessed UTF-8.
        const std::string alphabet="0123456789abcdef";
        std::string encoded;encoded.reserve(raw.size()*2);
        for(unsigned char b:raw){encoded+=alphabet[b>>4];encoded+=alphabet[b&15];}
        if(modern){
            // Modern other sections use Base64 for non-UTF8 blobs. Profile
            // sidecars are preserved separately as exact hex bytes.
            const auto rawSize=((raw.size()+2)/3)*4+4;
            Bytes data(rawSize);
            size_t actual=0;
            if(mbedtls_base64_encode(data.data(),data.size(),&actual,
                                     raw.data(),raw.size())==0)
                return json{{"base64",std::string(data.begin(),data.begin()+actual)}};
        }
        return json{{"hex",encoded}};
    }
}
json protections(const json& root){
    if(!root.is_object())return root;
    static const std::array<std::pair<const char*,const char*>,13> names={{
        {"a","accessMode"},{"c","expiryEnabled"},{"d","expiryTime"},
        {"e","noteEnabled"},{"f","hwidLockEnabled"},{"g","hwids"},
        {"h","loginHwidEnabled"},{"j","loginHwidAuthorizationRequired"},
        {"l","mobileDataOnly"},{"m","blockRoot"},{"o","providerLockEnabled"},
        {"p","providerCodes"},{"v","note"}
    }};
    json out=json::object();
    for(auto it=root.begin();it!=root.end();++it){
        std::string name=it.key();
        for(const auto& pair:names)if(name==pair.first){name=pair.second;break;}
        out[name]=it.value();
    }
    return out;
}
json decryptParsed(const json& envelope,const Material& material,bool modern){
    ensure(envelope.contains("i")&&envelope.at("i").is_object(),"HC_MISSING_MAIN");
    const auto main=jsonFromBytes(openSection(envelope.at("i"),material.key,material.aad));
    ensure(main.is_object(),"HC_MAIN_NOT_OBJECT");
    const json sections=envelope.value("j",json::array());
    json values=json::array();
    if(sections.is_array())values=sections;
    else if(sections.is_object())for(auto it=sections.begin();it!=sections.end();++it)values.push_back(it.value());
    else throw HCError("HC_BAD_SECTIONS");
    json profiles=json::array(),other=json::array();
    for(const auto& sec:values){
        ensure(sec.is_object(),"HC_BAD_SECTION");
        const auto label=str(sec,"a");
        Bytes plain=openSection(sec,material.key,material.aad);
        if(plain.size()>=4&&std::equal(plain.begin(),plain.begin()+4,"HPR1")){
            ensure(plain.size()>=44,"HC_INVALID_HPR1");
            Bytes nonce(plain.begin()+4,plain.begin()+28);
            Bytes ciphertext(plain.begin()+28,plain.end());
            Bytes aad=material.aad;addNull(aad);add(aad,label+":r");
            plain=xdec(material.key,nonce,aad,ciphertext);
        }
        Bytes sc;
        const bool hasSidecar=sidecar(sec,material.key,material.aad,sc);
        if(plain.size()>=4&&std::equal(plain.begin(),plain.begin()+4,"HPC1")){
            json parsed=profile(plain,label,modern);
            if(hasSidecar){
                json scValue=content(sc,modern);
                if(scValue.is_string())parsed["custom_payload_sidecar"]=scValue;
                else if(scValue.is_object()&&scValue.contains("hex"))
                    parsed["custom_payload_sidecar_hex"]=scValue["hex"];
                else if(scValue.is_object()&&scValue.contains("base64")){
                    // The original Python HCX4 decoder represents invalid
                    // UTF-8 sidecar bytes as exact hex, not Base64.
                    std::string encoded;
                    constexpr char digits[]="0123456789abcdef";
                    for(unsigned char c:sc){encoded.push_back(digits[c>>4]);encoded.push_back(digits[c&15]);}
                    parsed["custom_payload_sidecar_hex"]=encoded;
                }else parsed["custom_payload_sidecar"]=scValue;
            }
            profiles.push_back(std::move(parsed));
        }else{
            json entry={{"label",label},{"content",content(plain,modern)}};
            if(hasSidecar&&modern)entry["sidecar"]=content(sc,modern);
            other.push_back(std::move(entry));
        }
    }
    std::string version;
    const auto build=envelope.value("n",static_cast<uint64_t>(0));
    if(modern)version=build==899?"7.11.28 - Patch 1 (899)":"build-"+std::to_string(build);
    else{
        switch(build){
            case 756:version="7.9.21 (756)";break;
            case 759:version="7.9.24 (759)";break;
            case 766:version="7.9.28 (766)";break;
            case 789:version="7.10.7 (789)";break;
            case 810:version="7.10.12 (810)";break;
            case 831:version="7.10.19 (831)";break;
            case 848:version="7.10.25 (848)";break;
            case 859:version="7.11.1 (859)";break;
            case 864:version="7.11.8 (864)";break;
            default:version="build-"+std::to_string(build);
        }
    }
    json prot=json::object();
    if(main.contains("g"))prot=protections(main["g"]);
    json result={{"app_version",version},{"config",profiles},{"protections",prot}};
    if(modern){result["main"]=main;result["other_sections"]=other;}
    else if(!other.empty())result["other_sections"]=other;
    return result;
}
} // namespace
std::string decodeHttpCustom(const std::vector<unsigned char>& raw,
                             const std::string& password,const std::string& hwid){
    ensure(!raw.empty()&&raw.size()<=MAX_BYTES,"HC_INVALID_INPUT_SIZE");
    ensure(password.size()<=4096&&hwid.size()<=128,"HC_INVALID_CREDENTIAL");
    json env;
    if(openEnvelope(raw,true,env)){
        auto material=derive(env,password,hwid,true);
        return decryptParsed(env,material,true).dump(2,' ',false,json::error_handler_t::strict)+"\n";
    }
    if(openEnvelope(raw,false,env)){
        auto material=derive(env,password,hwid,false);
        return decryptParsed(env,material,false).dump(2,' ',false,json::error_handler_t::strict)+"\n";
    }
    throw HCError("HC_UNRECOGNIZED_FORMAT");
}
} // namespace spdecode::offline
