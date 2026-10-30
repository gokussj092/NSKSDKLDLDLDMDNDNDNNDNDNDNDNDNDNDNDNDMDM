#include "spdecode_hpke.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

namespace spdecode {
namespace {
using Bytes=std::vector<unsigned char>;
using Hash=std::array<unsigned char,32>;
constexpr size_t kHeader=71;
constexpr size_t kReplyHeader=27;
constexpr size_t kMaxWire=11U*1024U*1024U;
constexpr size_t kMaxReply=96U*1024U*1024U;
constexpr unsigned char kKemSuite[]={'K','E','M',0,0x20};
constexpr unsigned char kHpkeSuite[]={'H','P','K','E',0,0x20,0,1,0,2};
constexpr char kInfo[]="SPDECODE-V2-HPKE-TRANSPORT-1";
constexpr char kExport[]="SPDECODE-V2-HPKE-RESPONSE-KEY-NONCE-1";
constexpr char kResponseAad[]="SPDECODE-V2-HPKE-RESPONSE-AAD-1";

[[noreturn]] void invalid(){throw std::runtime_error("CLOUD_HPKE_NATIVE_INVALID");}
void required(int code){if(code!=0)invalid();}
void put16(Bytes& b,unsigned value){b.push_back((value>>8)&255);b.push_back(value&255);}
void put32(Bytes& b,size_t value){
    if(value>UINT32_MAX)invalid();
    for(int shift=24;shift>=0;shift-=8)b.push_back(static_cast<unsigned char>(value>>shift));
}
std::uint32_t read32(const unsigned char* p){
    return (std::uint32_t(p[0])<<24)|(std::uint32_t(p[1])<<16)|
           (std::uint32_t(p[2])<<8)|std::uint32_t(p[3]);
}
void append(Bytes& out,const unsigned char* p,size_t n){
    if(n==0)return; // Avoid pointer arithmetic on an empty vector's null data().
    if(p==nullptr)invalid();
    out.insert(out.end(),p,p+n);
}
void append(Bytes& out,const Bytes& b){append(out,b.data(),b.size());}
template<size_t N> void append(Bytes& out,const std::array<unsigned char,N>& v){
    append(out,v.data(),v.size());
}
void appendAscii(Bytes& out,const char* text){
    append(out,reinterpret_cast<const unsigned char*>(text),std::strlen(text));
}
void cleanse(Bytes& b){if(!b.empty())mbedtls_platform_zeroize(b.data(),b.size());}
template<size_t N> void cleanse(std::array<unsigned char,N>& b){
    mbedtls_platform_zeroize(b.data(),b.size());
}
struct WipeOnExit {
    Bytes& bytes;
    ~WipeOnExit(){cleanse(bytes);}
};
bool equal(const unsigned char* a,const unsigned char* b,size_t size){
    unsigned diff=0;
    for(size_t i=0;i<size;++i)diff|=static_cast<unsigned>(a[i]^b[i]);
    return diff==0;
}
Hash sha(const Bytes& value){
    Hash out{};
    required(mbedtls_sha256(value.data(),value.size(),out.data(),0));
    return out;
}
Hash hmac(const Hash& key,const Bytes& value){
    const mbedtls_md_info_t* md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if(md==nullptr)invalid();
    Hash out{};
    required(mbedtls_md_hmac(md,key.data(),key.size(),value.data(),value.size(),out.data()));
    return out;
}
Hash extract(const Bytes& salt,const Bytes& input){
    Hash s{};
    if(!salt.empty()){
        if(salt.size()!=s.size())invalid();
        std::copy(salt.begin(),salt.end(),s.begin());
    }
    const Hash result=hmac(s,input);
    cleanse(s);
    return result;
}
Bytes expand(const Hash& key,const Bytes& info,size_t length){
    if(length>255*32)invalid();
    Bytes out;out.reserve(length);
    Bytes previous;
    for(unsigned counter=1;out.size()<length;++counter){
        Bytes block=previous;
        append(block,info);
        block.push_back(static_cast<unsigned char>(counter));
        Hash next=hmac(key,block);
        cleanse(block);
        previous.assign(next.begin(),next.end());
        cleanse(next);
        const size_t take=std::min(previous.size(),length-out.size());
        append(out,previous.data(),take);
    }
    cleanse(previous);
    return out;
}
Hash labeledExtract(const Bytes& salt,const unsigned char* suite,size_t suiteLength,
                   const char* label,const Bytes& ikm){
    Bytes value;appendAscii(value,"HPKE-v1");
    append(value,suite,suiteLength);appendAscii(value,label);append(value,ikm);
    const Hash result=extract(salt,value);
    cleanse(value);
    return result;
}
Bytes labeledExpand(const Hash& prk,const unsigned char* suite,size_t suiteLength,
                  const char* label,const Bytes& context,size_t length){
    Bytes input;put16(input,length);appendAscii(input,"HPKE-v1");
    append(input,suite,suiteLength);appendAscii(input,label);append(input,context);
    Bytes out=expand(prk,input,length);
    cleanse(input);
    return out;
}
struct Rng {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr;
    Rng(){
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr);
        static const unsigned char personal[]="spdecode-native-hpke-v1";
        required(mbedtls_ctr_drbg_seed(&ctr,mbedtls_entropy_func,&entropy,
                                      personal,sizeof(personal)-1));
    }
    ~Rng(){mbedtls_ctr_drbg_free(&ctr);mbedtls_entropy_free(&entropy);}
    void generate(unsigned char* p,size_t n){required(mbedtls_ctr_drbg_random(&ctr,p,n));}
    Rng(const Rng&)=delete; Rng& operator=(const Rng&)=delete;
};
struct Ecdh {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point point;
    mbedtls_ecp_point peer;
    mbedtls_mpi secret;
    mbedtls_mpi dh;
    Ecdh(){
        mbedtls_ecp_group_init(&grp);
        mbedtls_ecp_point_init(&point);
        mbedtls_ecp_point_init(&peer);
        mbedtls_mpi_init(&secret);
        mbedtls_mpi_init(&dh);
        required(mbedtls_ecp_group_load(&grp,MBEDTLS_ECP_DP_CURVE25519));
    }
    ~Ecdh(){
        mbedtls_mpi_free(&dh);mbedtls_mpi_free(&secret);
        mbedtls_ecp_point_free(&peer);mbedtls_ecp_point_free(&point);
        mbedtls_ecp_group_free(&grp);
    }
    Ecdh(const Ecdh&)=delete;Ecdh& operator=(const Ecdh&)=delete;
};
struct Gcm {
    mbedtls_gcm_context ctx;
    explicit Gcm(const unsigned char* key){
        mbedtls_gcm_init(&ctx);
        required(mbedtls_gcm_setkey(&ctx,MBEDTLS_CIPHER_ID_AES,key,256));
    }
    ~Gcm(){mbedtls_gcm_free(&ctx);}
    Gcm(const Gcm&)=delete;Gcm& operator=(const Gcm&)=delete;
};
struct Stored {
    std::array<unsigned char,44> material{};
    std::array<unsigned char,16> id{};
    Hash requestHash{};
    ~Stored(){cleanse(material);cleanse(id);cleanse(requestHash);}
};
std::mutex locks;
std::map<std::uint64_t,Stored> active;

} // namespace

PreparedEnvelope hpkePrepare(int operation,const Bytes& metadata,
    const Bytes& attachment,const std::array<unsigned char,40>& pin) {
    if(operation<1||operation>17||operation==3 ||
       metadata.size()<2||metadata.size()>1024U*1024U ||
       (operation==5?(attachment.empty()||attachment.size()>8U*1024U*1024U):
                     !attachment.empty()))invalid();
    if(metadata.size()+attachment.size()+4+kHeader+16>kMaxWire)invalid();

    Bytes publicKey(pin.begin()+8,pin.end());
    const Hash pinDigest=sha(publicKey);
    if(!equal(pin.data(),pinDigest.data(),8))invalid();

    Rng rng;
    Ecdh ecdh;
    required(mbedtls_ecdh_gen_public(&ecdh.grp,&ecdh.secret,&ecdh.point,
                                    mbedtls_ctr_drbg_random,&rng.ctr));
    std::array<unsigned char,32> enc{};
    size_t olen=0;
    required(mbedtls_ecp_point_write_binary(&ecdh.grp,&ecdh.point,
                                           MBEDTLS_ECP_PF_UNCOMPRESSED,&olen,
                                           enc.data(),enc.size()));
    if(olen!=32)invalid();
    required(mbedtls_ecp_point_read_binary(&ecdh.grp,&ecdh.peer,publicKey.data(),32));
    required(mbedtls_ecdh_compute_shared(&ecdh.grp,&ecdh.dh,&ecdh.peer,&ecdh.secret,
                                        mbedtls_ctr_drbg_random,&rng.ctr));
    std::array<unsigned char,32> dh{};
    required(mbedtls_mpi_write_binary_le(&ecdh.dh,dh.data(),dh.size()));
    // RFC 9180 DHKEM(X25519,HKDF-SHA256) rejects all-zero shared secrets.
    std::array<unsigned char,32> zero{};
    if(equal(dh.data(),zero.data(),32))invalid();

    Bytes kemContext;append(kemContext,enc);append(kemContext,publicKey);
    Bytes dhBytes(dh.begin(),dh.end());
    Hash eae=labeledExtract({},kKemSuite,sizeof(kKemSuite),"eae_prk",dhBytes);
    cleanse(dhBytes);cleanse(dh);
    Bytes sharedSecret=labeledExpand(eae,kKemSuite,sizeof(kKemSuite),
                                          "shared_secret",kemContext,32);
    cleanse(eae);
    Bytes infoHashData;appendAscii(infoHashData,kInfo);
    const Hash pskIdHash=labeledExtract({},kHpkeSuite,sizeof(kHpkeSuite),"psk_id_hash",{});
    const Hash infoHash=labeledExtract({},kHpkeSuite,sizeof(kHpkeSuite),
                                      "info_hash",infoHashData);
    Bytes scheduleContext; scheduleContext.push_back(0); // HPKE base mode.
    append(scheduleContext,pskIdHash);append(scheduleContext,infoHash);
    Hash secret=labeledExtract(sharedSecret,kHpkeSuite,sizeof(kHpkeSuite),"secret",{});
    cleanse(sharedSecret);
    Bytes key=labeledExpand(secret,kHpkeSuite,sizeof(kHpkeSuite),"key",scheduleContext,32);
    WipeOnExit wipeKey{key};
    Bytes nonce=labeledExpand(secret,kHpkeSuite,sizeof(kHpkeSuite),"base_nonce",scheduleContext,12);
    WipeOnExit wipeNonce{nonce};
    Bytes exporterSecret=labeledExpand(secret,kHpkeSuite,sizeof(kHpkeSuite),
                                              "exp",scheduleContext,32);
    Hash exporterKey{};std::copy(exporterSecret.begin(),exporterSecret.end(),exporterKey.begin());
    cleanse(exporterSecret);cleanse(secret);
    Bytes exportContext;appendAscii(exportContext,kExport);
    Bytes responseMaterial=labeledExpand(exporterKey,kHpkeSuite,sizeof(kHpkeSuite),
                                         "sec",exportContext,44);
    cleanse(exporterKey);
    if(key.size()!=32||nonce.size()!=12||responseMaterial.size()!=44)invalid();

    Stored state;
    rng.generate(state.id.data(),state.id.size());
    std::copy(responseMaterial.begin(),responseMaterial.end(),state.material.begin());
    cleanse(responseMaterial);

    Bytes payload;
    WipeOnExit wipePayload{payload};
    payload.reserve(4+metadata.size()+attachment.size());
    put32(payload,metadata.size());append(payload,metadata);append(payload,attachment);
    Bytes header;header.reserve(kHeader);
    appendAscii(header,"SPH2");header.push_back(1);
    put16(header,0x20);put16(header,1);put16(header,2);
    append(header,pin.data(),8);append(header,state.id);append(header,enc);
    put32(header,payload.size()+16);
    if(header.size()!=kHeader)invalid();
    Bytes aad=header;aad.push_back(static_cast<unsigned char>(operation));
    Bytes encrypted(payload.size()+16);
    Gcm gcm(key.data());
    required(mbedtls_gcm_crypt_and_tag(&gcm.ctx,MBEDTLS_GCM_ENCRYPT,payload.size(),
       nonce.data(),nonce.size(),aad.data(),aad.size(),payload.data(),
       encrypted.data(),16,encrypted.data()+payload.size()));
    cleanse(payload);cleanse(key);cleanse(nonce);
    Bytes wire=std::move(header);append(wire,encrypted);cleanse(encrypted);
    state.requestHash=sha(wire);
    std::uint64_t handle=0;
    {
        std::lock_guard<std::mutex> guard(locks);
        if(active.size()>=64)invalid();
        for(int i=0;i<8;++i){
            rng.generate(reinterpret_cast<unsigned char*>(&handle),sizeof(handle));
            if(handle!=0 && active.find(handle)==active.end())break;
            handle=0;
        }
        if(handle==0)invalid();
        active.emplace(handle,std::move(state));
    }
    return {std::move(wire),handle};
}

std::vector<unsigned char> hpkeOpen(std::uint64_t handle,int status,
  const Bytes& wire,const Bytes& response) {
    Stored state;
    {
        std::lock_guard<std::mutex> guard(locks);
        auto it=active.find(handle);
        if(it==active.end())invalid();
        state=std::move(it->second);
        active.erase(it);
    }
    if(status<100||status>599||response.size()<kReplyHeader+16||
       response.size()>kMaxReply+kReplyHeader+16||wire.size()<kHeader+16||
       wire.size()>kMaxWire)invalid();
    if(std::memcmp(response.data(),"SPR2",4)!=0||response[4]!=1 ||
       (unsigned(response[5])<<8 | unsigned(response[6]))!=static_cast<unsigned>(status)||
       !equal(response.data()+7,state.id.data(),16)||
       read32(response.data()+23)!=response.size()-kReplyHeader)invalid();
    if(!equal(sha(wire).data(),state.requestHash.data(),32))invalid();
    Bytes aad;appendAscii(aad,kResponseAad);
    append(aad,state.requestHash);
    append(aad,response.data(),kReplyHeader);
    Gcm gcm(state.material.data());
    const size_t encryptedLength=response.size()-kReplyHeader-16;
    Bytes plaintext(encryptedLength);
    required(mbedtls_gcm_auth_decrypt(&gcm.ctx,encryptedLength,
       state.material.data()+32,12,aad.data(),aad.size(),
       response.data()+kReplyHeader+encryptedLength,16,
       response.data()+kReplyHeader,plaintext.data()));
    return plaintext;
}

void hpkeDiscard(std::uint64_t handle) {
    std::lock_guard<std::mutex> guard(locks);
    active.erase(handle);
}
} // namespace spdecode
