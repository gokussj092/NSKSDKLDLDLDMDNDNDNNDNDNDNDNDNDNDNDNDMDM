#include "spdecode_catalog.h"
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/private_access.h>
#include <mbedtls/platform_util.h>
#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <map>
#include <mutex>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace spdecode {
namespace {
using Bytes=CatalogBytes;
constexpr std::size_t kMaxPlain=32U*1024U*1024U;
[[noreturn]] void invalid() { throw std::runtime_error("CLOUD_CATALOG_AUTH_FAILED"); }
void required(int rc) { if(rc!=0)invalid(); }
void wipe(Bytes& b){if(!b.empty())mbedtls_platform_zeroize(b.data(),b.size());}
struct Scrub {
    Bytes& bytes;
    ~Scrub(){wipe(bytes);}
};
template<std::size_t N> struct ScrubArray {
    std::array<unsigned char,N>& value;
    ~ScrubArray(){mbedtls_platform_zeroize(value.data(),value.size());}
};
struct Rng {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    Rng(){
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&drbg);
        const unsigned char personal[]="v3.2/9s";
        if(mbedtls_ctr_drbg_seed(&drbg,mbedtls_entropy_func,&entropy,
                                      personal,sizeof(personal)-1)!=0){
            mbedtls_ctr_drbg_free(&drbg);mbedtls_entropy_free(&entropy);invalid();
        }
    }
    ~Rng(){mbedtls_ctr_drbg_free(&drbg);mbedtls_entropy_free(&entropy);}
};
struct Key {
    mbedtls_pk_context pk;
    Key(){mbedtls_pk_init(&pk);}
    ~Key(){mbedtls_pk_free(&pk);}
};
struct Shared {
    mbedtls_mpi dh;
    Shared(){mbedtls_mpi_init(&dh);}
    ~Shared(){mbedtls_mpi_free(&dh);}
};
struct Gcm {
    mbedtls_gcm_context ctx;
    Gcm(){mbedtls_gcm_init(&ctx);}
    ~Gcm(){mbedtls_gcm_free(&ctx);}
};
bool urlSafe(char c){
    return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||
           (c>='0'&&c<='9')||c=='-'||c=='_';
}
Bytes decode(const std::string& source,std::size_t min,std::size_t max){
    if(source.empty()||source.size()>((max+2)/3)*4 ||
       !std::all_of(source.begin(),source.end(),urlSafe))invalid();
    std::string text=source;
    for(char& c:text)if(c=='-')c='+';else if(c=='_')c='/';
    if(text.size()%4==1)invalid();
    text.append((4-text.size()%4)%4,'=');
    Bytes out((text.size()/4)*3+3);
    size_t count=0;
    required(mbedtls_base64_decode(out.data(),out.size(),&count,
                                   reinterpret_cast<const unsigned char*>(text.data()),
                                   text.size()));
    if(count<min||count>max)invalid();
    out.resize(count);
    Bytes canonical(((count+2)/3)*4+4);
    size_t encoded=0;
    required(mbedtls_base64_encode(canonical.data(),canonical.size(),&encoded,
                                   out.data(),out.size()));
    std::string check(reinterpret_cast<const char*>(canonical.data()),encoded);
    for(char& c:check)if(c=='+')c='-';else if(c=='/')c='_';
    while(!check.empty()&&check.back()=='=')check.pop_back();
    if(check!=source)invalid();
    return out;
}
std::array<unsigned char,32> mac(const unsigned char* key,std::size_t keyLength,
                                  const unsigned char* data,std::size_t size) {
    auto md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if(!md)invalid();
    std::array<unsigned char,32> result{};
    required(mbedtls_md_hmac(md,key,keyLength,data,size,result.data()));
    return result;
}

// Per-request native-only P-256 ephemeral key material. All exported handles
// are random, bounded and single-use. Do not retain native pointers in Java.
struct PendingCatalog {
    Bytes privateDer;
    std::string publicKey;
    std::chrono::steady_clock::time_point created;
};
std::mutex pendingMutex;
std::map<std::uint64_t,PendingCatalog> pending;
constexpr std::size_t kMaxPending=64;
constexpr auto kPendingTtl=std::chrono::seconds(180);

void pruneCatalogLocked(){
    const auto now=std::chrono::steady_clock::now();
    for(auto it=pending.begin();it!=pending.end();){
        if(now-it->second.created>kPendingTtl){
            wipe(it->second.privateDer);
            it=pending.erase(it);
        }else ++it;
    }
}
std::string encodeUrl(const unsigned char* bytes,std::size_t length){
    Bytes result(((length+2)/3)*4+4);
    size_t size=0;
    required(mbedtls_base64_encode(result.data(),result.size(),&size,bytes,length));
    std::string out(reinterpret_cast<const char*>(result.data()),size);
    for(char& c:out)if(c=='+')c='-';else if(c=='/')c='_';
    while(!out.empty()&&out.back()=='=')out.pop_back();
    return out;
}
} // namespace

CatalogRecipient beginCatalog(){
    Rng rng;
    Key key;
    required(mbedtls_pk_setup(&key.pk,mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)));
    required(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,mbedtls_pk_ec(key.pk),
                                 mbedtls_ctr_drbg_random,&rng.drbg));
    Bytes pub(256);
    const int pubSize=mbedtls_pk_write_pubkey_der(&key.pk,pub.data(),pub.size());
    if(pubSize!=91)invalid();
    const auto recipient=encodeUrl(pub.data()+pub.size()-pubSize,
                                   static_cast<size_t>(pubSize));
    Bytes der(512);
    Scrub scrubDer{der};
    const int derSize=mbedtls_pk_write_key_der(&key.pk,der.data(),der.size());
    if(derSize<48||derSize>512)invalid();
    Bytes secret(der.end()-derSize,der.end());
    Scrub scrubSecret{secret};
    std::uint64_t handle=0;
    std::array<unsigned char,8> random{};
    std::lock_guard<std::mutex> lock(pendingMutex);
    pruneCatalogLocked();
    if(pending.size()>=kMaxPending)invalid();
    for(int attempts=0;attempts<16;++attempts){
        required(mbedtls_ctr_drbg_random(&rng.drbg,random.data(),random.size()));
        handle=0;
        for(auto c:random)handle=(handle<<8)|c;
        handle &= 0x7fffffffffffffffULL; // representable by Java Long
        if(handle!=0 && pending.count(handle)==0)break;
        handle=0;
    }
    if(handle==0)invalid();
    pending.emplace(handle,PendingCatalog{std::move(secret),recipient,
                                         std::chrono::steady_clock::now()});
    return CatalogRecipient{handle,recipient};
}
void discardCatalog(std::uint64_t handle){
    std::lock_guard<std::mutex> lock(pendingMutex);
    const auto it=pending.find(handle);
    if(it!=pending.end()){wipe(it->second.privateDer);pending.erase(it);}
}
CatalogBytes openCatalogHandle(std::uint64_t handle,const std::string& recipient,
   const std::string& purpose,const std::string& sender,const std::string& salt,
   const std::string& iv,int plainBytes,const std::string& data){
    PendingCatalog entry;
    {
        std::lock_guard<std::mutex> lock(pendingMutex);
        pruneCatalogLocked();
        auto it=pending.find(handle);
        if(handle==0||it==pending.end())invalid();
        entry=std::move(it->second);
        pending.erase(it);
    }
    Scrub wipeEntry{entry.privateDer};
    if(entry.publicKey!=recipient)invalid();
    return openCatalog(entry.privateDer,recipient,purpose,sender,
                       salt,iv,plainBytes,data);
}

CatalogBytes openCatalog(const CatalogBytes& privatePkcs8,const std::string& recipient,
                         const std::string& purpose,const std::string& sender,
                         const std::string& saltText,const std::string& ivText,
                         int plainBytes,const std::string& dataText){
    if((purpose!="catalog"&&purpose!="icon")||plainBytes<1||
       static_cast<std::size_t>(plainBytes)>(purpose=="icon"?4U*1024U*1024U:kMaxPlain)||
       privatePkcs8.size()<48||privatePkcs8.size()>2048)invalid();
    auto recipientDer=decode(recipient,91,91);
    auto serverDer=decode(sender,91,91);
    auto salt=decode(saltText,32,32);
    auto iv=decode(ivText,12,12);
    auto data=decode(dataText,17,kMaxPlain+2048);
    if(data.size()<17)invalid();
    Rng rng;
    Key own,peer,recipientKey;
    required(mbedtls_pk_parse_key(&own.pk,privatePkcs8.data(),privatePkcs8.size(),
        nullptr,0,mbedtls_ctr_drbg_random,&rng.drbg));
    required(mbedtls_pk_parse_public_key(&peer.pk,serverDer.data(),serverDer.size()));
    required(mbedtls_pk_parse_public_key(&recipientKey.pk,recipientDer.data(),recipientDer.size()));
    if(mbedtls_pk_get_type(&own.pk)!=MBEDTLS_PK_ECKEY ||
       mbedtls_pk_get_type(&peer.pk)!=MBEDTLS_PK_ECKEY ||
       mbedtls_pk_get_type(&recipientKey.pk)!=MBEDTLS_PK_ECKEY)invalid();
    auto* ownEc=mbedtls_pk_ec(own.pk);
    auto* peerEc=mbedtls_pk_ec(peer.pk);
    auto* recipientEc=mbedtls_pk_ec(recipientKey.pk);
    if(!ownEc||!peerEc||!recipientEc ||
       ownEc->MBEDTLS_PRIVATE(grp).id!=MBEDTLS_ECP_DP_SECP256R1 ||
       peerEc->MBEDTLS_PRIVATE(grp).id!=MBEDTLS_ECP_DP_SECP256R1 ||
       recipientEc->MBEDTLS_PRIVATE(grp).id!=MBEDTLS_ECP_DP_SECP256R1)invalid();
    required(mbedtls_ecp_check_pubkey(&peerEc->MBEDTLS_PRIVATE(grp),&peerEc->MBEDTLS_PRIVATE(Q)));
    required(mbedtls_ecp_check_pubkey(&recipientEc->MBEDTLS_PRIVATE(grp),&recipientEc->MBEDTLS_PRIVATE(Q)));
    // The recipient SPKI is authenticated as part of the GCM AAD; a
    // mismatched private key cannot authenticate the server ciphertext.
    Shared shared;
    required(mbedtls_ecdh_compute_shared(&ownEc->MBEDTLS_PRIVATE(grp),&shared.dh,&peerEc->MBEDTLS_PRIVATE(Q),
        &ownEc->MBEDTLS_PRIVATE(d),mbedtls_ctr_drbg_random,&rng.drbg));
    Bytes sharedBytes(32);
    Scrub wipeShared{sharedBytes};
    required(mbedtls_mpi_write_binary(&shared.dh,sharedBytes.data(),32));
    auto prk=mac(salt.data(),salt.size(),sharedBytes.data(),sharedBytes.size());
    ScrubArray<32> scrubPrk{prk};
    Bytes info;
    Scrub wipeInfo{info};
    const std::string label="SPDECODE-CATALOG-1:"+purpose;
    info.insert(info.end(),label.begin(),label.end());
    info.push_back(1);
    auto key=mac(prk.data(),prk.size(),info.data(),info.size());
    ScrubArray<32> scrubKey{key};
    mbedtls_platform_zeroize(prk.data(),prk.size());
    const std::string aad="SPDECODE-CATALOG-1\n"+purpose+"\n"+
                          recipient+"\n"+sender+"\n"+std::to_string(plainBytes);
    Gcm gcm;
    required(mbedtls_gcm_setkey(&gcm.ctx,MBEDTLS_CIPHER_ID_AES,key.data(),256));
    mbedtls_platform_zeroize(key.data(),key.size());
    Bytes packed(data.size()-16);
    // The final 16 bytes are the authenticated tag and are never decrypted.
    try { required(mbedtls_gcm_auth_decrypt(&gcm.ctx,packed.size(),
        iv.data(),iv.size(),reinterpret_cast<const unsigned char*>(aad.data()),aad.size(),
        data.data()+packed.size(),16,data.data(),packed.data()));
    }catch(...){wipe(packed);throw;}
    return packed;
}
} // namespace spdecode
