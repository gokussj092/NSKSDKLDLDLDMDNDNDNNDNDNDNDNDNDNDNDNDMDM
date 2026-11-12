#include "spdecode_security.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <array>
#include <cstdint>
#include <ctime>
#include <stdexcept>
#include <string>
#include <vector>

namespace spdecode {
namespace {
void invalid(){throw std::runtime_error("CLOUD_NATIVE_PROOF_INVALID");}
std::array<unsigned char,32> hash(const unsigned char* data,std::size_t n) {
    if(n>0 && data==nullptr)invalid();
    static constexpr unsigned char empty=0;
    std::array<unsigned char,32> digest{};
    if(mbedtls_sha256(n?data:&empty,n,digest.data(),0)!=0)invalid();
    return digest;
}
std::string hexDigest(const unsigned char* data,std::size_t len) {
    auto digest=hash(data,len);
    static const char symbols[]="0123456789abcdef";
    std::string hex;hex.reserve(64);
    for(unsigned char b:digest) {
        hex.push_back(symbols[b>>4]);hex.push_back(symbols[b&15]);
    }
    mbedtls_platform_zeroize(digest.data(),digest.size());
    return hex;
}
std::string base64Url(const unsigned char* data,std::size_t size) {
    static const char alphabet[]=
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;out.reserve((size*4+2)/3);
    for(std::size_t i=0;i<size;i+=3) {
        const unsigned a=data[i],b=i+1<size?data[i+1]:0,c=i+2<size?data[i+2]:0;
        out.push_back(alphabet[a>>2]);
        out.push_back(alphabet[((a&3)<<4)|(b>>4)]);
        if(i+1<size)out.push_back(alphabet[((b&15)<<2)|(c>>6)]);
        if(i+2<size)out.push_back(alphabet[c&63]);
    }
    return out;
}
std::string randomNonce() {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context rng;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&rng);
    const unsigned char personal[]="spdecode-v2-pop-nonce";
    const int seed=mbedtls_ctr_drbg_seed(&rng,mbedtls_entropy_func,&entropy,
                                       personal,sizeof(personal)-1);
    std::array<unsigned char,24> bytes{};
    const int generated=seed==0?mbedtls_ctr_drbg_random(&rng,bytes.data(),bytes.size()):-1;
    mbedtls_ctr_drbg_free(&rng);
    mbedtls_entropy_free(&entropy);
    if(generated!=0)invalid();
    const std::string result=base64Url(bytes.data(),bytes.size());
    mbedtls_platform_zeroize(bytes.data(),bytes.size());
    return result;
}
bool acceptableVersion(const std::string& version){
    if(version.size()<5||version.size()>11)return false;
    unsigned dots=0;
    for(char c:version){if(c=='.')++dots;else if(c<'0'||c>'9')return false;}
    return dots==2;
}
bool acceptableNonce(const std::string& value) {
    if(value.size()!=32)return false;
    for(char c:value) if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||
        (c>='0'&&c<='9')||c=='-'||c=='_'))return false;
    return true;
}
} // namespace

std::string sha256Hex(const unsigned char* data,std::size_t size){
    return hexDigest(data,size);
}
std::string formatProof(int op,const std::string& version,
                        const unsigned char* body,std::size_t size,
                        const std::string& bearer,const std::string& timestamp,
                        const std::string& nonce){
    if(op<1||op>24||op==3||!acceptableVersion(version)||bearer.size()>2048||
       timestamp.size()<10||timestamp.size()>11||!acceptableNonce(nonce)||
       size>12U*1024U*1024U)invalid();
    for(char c:timestamp)if(c<'0'||c>'9')invalid();
    for(char c:bearer)if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||
         (c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'))invalid();
    const std::string hashedBearer=hexDigest(
        reinterpret_cast<const unsigned char*>(bearer.data()),bearer.size());
    const std::string hashedBody=hexDigest(body,size);
    return "SPDECODE-POP-V2\nPOST\n"+std::to_string(op)+"\n"+version+"\n"+
        timestamp+"\n"+nonce+"\n"+hashedBearer+"\n"+hashedBody;
}
RequestProof prepareProof(int operation,const std::string& version,
                          const unsigned char* data,std::size_t size,
                          const std::string& bearer){
    RequestProof proof;
    proof.timestamp=std::to_string(static_cast<std::int64_t>(std::time(nullptr)));
    proof.nonce=randomNonce();
    proof.message=formatProof(operation,version,data,size,bearer,
                              proof.timestamp,proof.nonce);
    return proof;
}
namespace {
bool urlChars(const std::string& value, std::size_t min, std::size_t max) {
    if(value.size()<min || value.size()>max)return false;
    for(unsigned char c:value) {
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
             (c>='0'&&c<='9')||c=='-'||c=='_'))return false;
    }
    return true;
}
bool challengeIdChars(const std::string& value) {
    if(value.size()!=36)return false;
    for(unsigned char c:value)
        if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')||c=='-'))return false;
    return true;
}
}
bool validClassicChallenge(const std::string& nonce,const std::string& id,
                           const std::string& version) {
    return urlChars(nonce,43,43) && challengeIdChars(id) && version=="v2";
}
bool validActionChallenge(const std::string& hash,const std::string& id,
                          std::int64_t project) {
    const bool inlineId=id.size()==35&&id.substr(0,3)=="i2."&&urlChars(id.substr(3),32,32);
    return project>0 && urlChars(hash,43,43) && (challengeIdChars(id)||inlineId);
}
ActionBinding inlineActionBinding(int op,const std::string& bearer,
                                 const unsigned char* data,std::size_t size) {
    if((op!=4&&op!=5&&op!=6&&op!=7&&op!=8&&op!=9&&op!=12&&op!=18&&op!=21&&op!=23)||
       bearer.empty()||bearer.size()>2048||size>12U*1024U*1024U)invalid();
    for(unsigned char c:bearer)if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
        (c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'))invalid();
    const auto nonce=randomNonce();
    std::string message="SPDECODE-ACTION-V2\n"+bearer+"\n"+std::to_string(op)+"\n"+
        hexDigest(data,size)+"\n"+nonce;
    auto digest=hash(reinterpret_cast<const unsigned char*>(message.data()),message.size());
    const auto encoded=base64Url(digest.data(),digest.size());
    mbedtls_platform_zeroize(message.data(),message.size());
    mbedtls_platform_zeroize(digest.data(),digest.size());
    return {"i2."+nonce,encoded};
}
bool validPlayNonce(const std::string& nonce){
    return urlChars(nonce,16,500);
}
std::string makeAliasSuffix(){
    // Eight URL-safe Base64 characters encode the first six random bytes.
    return randomNonce().substr(0,8);
}
std::string playNonce(const std::string& nonce,const std::string& id,
                      const std::string& publicKey) {
    if(nonce.size()!=43||id.size()!=36||publicKey.size()<120||publicKey.size()>128)
        invalid();
    const std::string text="SPDECODE-KEY-V2\n"+nonce+"\n"+id+"\n"+publicKey;
    auto digest=hash(reinterpret_cast<const unsigned char*>(text.data()),text.size());
    const std::string result=base64Url(digest.data(),digest.size());
    mbedtls_platform_zeroize(digest.data(),digest.size());
    return result;
}
} // namespace spdecode
