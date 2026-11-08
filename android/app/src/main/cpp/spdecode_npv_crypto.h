#pragma once
#include <mbedtls/base64.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
namespace spdecode::offline::npv {
using Bytes=std::vector<unsigned char>;
using json=nlohmann::json;
struct Error:std::runtime_error{using std::runtime_error::runtime_error;};
inline void need(bool condition,const char* text){if(!condition)throw Error(text);}
inline Bytes raw(const std::string& value){return Bytes(value.begin(),value.end());}
inline std::string str(const Bytes& bytes){return std::string(bytes.begin(),bytes.end());}
inline void append(Bytes& target,const Bytes& source){target.insert(target.end(),source.begin(),source.end());}
inline void append(Bytes& target,const std::string& source){target.insert(target.end(),source.begin(),source.end());}
inline void num16(Bytes& target,uint16_t value){target.push_back(value>>8);target.push_back(value&255);}
inline void num32(Bytes& target,uint32_t value){
    target.push_back(value>>24);target.push_back((value>>16)&255);
    target.push_back((value>>8)&255);target.push_back(value&255);
}
inline uint16_t u16(const Bytes& data,size_t offset){
    need(offset+2<=data.size(),"NPV_TRUNCATED");
    return (static_cast<uint16_t>(data[offset])<<8)|data[offset+1];
}
inline uint32_t u32(const Bytes& data,size_t offset){
    need(offset+4<=data.size(),"NPV_TRUNCATED");
    return (static_cast<uint32_t>(data[offset])<<24)|
           (static_cast<uint32_t>(data[offset+1])<<16)|
           (static_cast<uint32_t>(data[offset+2])<<8)|data[offset+3];
}
inline Bytes slice(const Bytes& raw,size_t offset,size_t count){
    need(offset<=raw.size()&&count<=raw.size()-offset,"NPV_TRUNCATED");
    return Bytes(raw.begin()+offset,raw.begin()+offset+count);
}
inline std::string hex(const Bytes& raw){
    static const char* dig="0123456789abcdef";std::string v;
    v.reserve(raw.size()*2);
    for(auto c:raw){v.push_back(dig[c>>4]);v.push_back(dig[c&15]);}
    return v;
}
inline Bytes hash(const Bytes& data){
    Bytes out(32);
    need(mbedtls_sha256(data.data(),data.size(),out.data(),0)==0,"NPV_SHA256_FAILED");
    return out;
}
inline Bytes mac(const Bytes& key,const Bytes& data){
    const auto* md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    need(md!=nullptr,"NPV_HMAC_NOT_AVAILABLE");
    Bytes out(32);
    need(mbedtls_md_hmac(md,key.data(),key.size(),data.data(),data.size(),
                        out.data())==0,"NPV_HMAC_FAILED");
    return out;
}
inline Bytes derive(const Bytes& ikm,const Bytes& salt,const Bytes& info){
    const auto* md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    need(md!=nullptr,"NPV_KDF_NOT_AVAILABLE");
    Bytes out(32);
    need(mbedtls_hkdf(md,salt.data(),salt.size(),ikm.data(),ikm.size(),
                      info.data(),info.size(),out.data(),out.size())==0,
                      "NPV_KDF_FAILED");
    return out;
}
inline Bytes pbkdf2(const std::string& pw,const Bytes& salt,uint32_t iterations){
    need(!pw.empty()&&pw.size()<=4096&&iterations>=1&&iterations<=10000000,
         "NPV_PBKDF2_LIMIT");
    Bytes out(32);
    need(mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
         reinterpret_cast<const unsigned char*>(pw.data()),pw.size(),
         salt.data(),salt.size(),iterations,32,out.data())==0,"NPV_PBKDF2_FAILED");
    return out;
}
inline std::string url(const Bytes& data){
    Bytes encoded((data.size()+2)/3*4+4);size_t length=0;
    need(mbedtls_base64_encode(encoded.data(),encoded.size(),&length,
         data.data(),data.size())==0,"NPV_B64_FAILED");
    std::string output(reinterpret_cast<const char*>(encoded.data()),length);
    for(char& c:output){if(c=='+')c='-';else if(c=='/')c='_';}
    while(!output.empty()&&output.back()=='=')output.pop_back();
    return output;
}
inline Bytes unurl(const std::string& value,size_t limit=16384){
    need(!value.empty()&&value.size()<=limit,"NPV_INVALID_CREDENTIAL");
    std::string encoded=value;
    for(char& c:encoded){
        if(c=='-')c='+';
        else if(c=='_')c='/';
        need((c>='a'&&c<='z')||(c>='A'&&c<='Z')||
             (c>='0'&&c<='9')||c=='+'||c=='/'||c=='=',"NPV_INVALID_BASE64");
    }
    encoded.append((4-encoded.size()%4)%4,'=');
    Bytes out(encoded.size()*3/4+5);size_t length=0;
    need(mbedtls_base64_decode(out.data(),out.size(),&length,
        reinterpret_cast<const unsigned char*>(encoded.data()),encoded.size())==0,
        "NPV_INVALID_BASE64");
    out.resize(length);
    need(url(out)==value,"NPV_NONCANONICAL_BASE64");
    return out;
}
inline Bytes openChaCha(const Bytes& key,const Bytes& nonce,const Bytes& sealed,
                        const Bytes& aad){
    need(key.size()==32&&nonce.size()==12&&sealed.size()>=16,
         "NPV_INVALID_CHACHA_INPUT");
    Bytes clear(sealed.size()-16);
    mbedtls_chachapoly_context context;mbedtls_chachapoly_init(&context);
    int rc=mbedtls_chachapoly_setkey(&context,key.data());
    if(rc==0)rc=mbedtls_chachapoly_auth_decrypt(&context,clear.size(),
         nonce.data(),aad.data(),aad.size(),sealed.data()+clear.size(),
         sealed.data(),clear.data());
    mbedtls_chachapoly_free(&context);
    need(rc==0,"AUTH_FAILED");return clear;
}
inline Bytes openGcm(const Bytes& key,const Bytes& nonce,const Bytes& sealed,
                     const Bytes& aad){
    need(key.size()==32&&nonce.size()==12&&sealed.size()>=16,
         "NPV_INVALID_GCM_INPUT");
    Bytes clear(sealed.size()-16);
    mbedtls_gcm_context context;mbedtls_gcm_init(&context);
    int rc=mbedtls_gcm_setkey(&context,MBEDTLS_CIPHER_ID_AES,key.data(),256);
    if(rc==0)rc=mbedtls_gcm_auth_decrypt(&context,clear.size(),
        nonce.data(),nonce.size(),aad.data(),aad.size(),
        sealed.data()+clear.size(),16,sealed.data(),clear.data());
    mbedtls_gcm_free(&context);
    need(rc==0,"AUTH_FAILED");
    return clear;
}
inline json parse(const Bytes& data){
    // JSON parser is strict about invalid UTF-8, numbers and syntax.
    try{return json::parse(data.begin(),data.end());}
    catch(...){throw Error("NPV_INVALID_JSON");}
}
inline std::string canonical(const json& value){
    try{return value.dump(-1,' ',false,json::error_handler_t::strict);}
    catch(...){throw Error("NPV_INVALID_CANONICAL_JSON");}
}
inline void embedded(json& v,int depth=0){
    need(depth<=64,"NPV_NESTING_LIMIT");
    if(v.is_object()){
        for(auto it=v.begin();it!=v.end();++it)embedded(it.value(),depth+1);
    }else if(v.is_array()){
        for(auto& e:v)embedded(e,depth+1);
    }else if(v.is_string()){
        auto text=v.get<std::string>();
        if(text.rfind("npvs1:",0)!=0)return;
        std::string value=text.substr(6);
        value.erase(std::remove_if(value.begin(),value.end(),
          [](char c){return c==' '||c=='\n'||c=='\r'||c=='\t';}),value.end());
        const Bytes decoded=unurl(value,8*1024*1024);
        const auto strValue=str(decoded);
        if(strValue.rfind("npvs1:",0)==0){v=strValue;embedded(v,depth+1);return;}
        size_t i=0;
        while(i<strValue.size()&&std::isspace(static_cast<unsigned char>(strValue[i])))i++;
        if(i<strValue.size()&&(strValue[i]=='{'||strValue[i]=='[')){
            try{v=parse(decoded);embedded(v,depth+1);return;}
            catch(const Error&){}
        }
        v=strValue;
        // Verify all generated strings survive a strict UTF-8 serialization.
        try{(void)v.dump(-1,' ',false,json::error_handler_t::strict);}
        catch(...){throw Error("NPV_INVALID_UTF8");}
    }
}
struct Curve {
    mbedtls_ecp_group group;
    Curve(){
        mbedtls_ecp_group_init(&group);
        need(mbedtls_ecp_group_load(&group,MBEDTLS_ECP_DP_SECP256R1)==0,
             "NPV_CURVE_UNAVAILABLE");
    }
    ~Curve(){mbedtls_ecp_group_free(&group);}
};
struct Point {
    mbedtls_ecp_point q;
    Point(){mbedtls_ecp_point_init(&q);}
    ~Point(){mbedtls_ecp_point_free(&q);}
};
struct Mpi {
    mbedtls_mpi v;
    Mpi(){mbedtls_mpi_init(&v);}
    ~Mpi(){mbedtls_mpi_free(&v);}
};
inline void pointRead(Curve& curve,Point& q,const Bytes& packed){
    need(packed.size()==33&&(packed[0]==2||packed[0]==3),
         "NPV_BAD_COMPRESSED_POINT");
    Mpi x,y,rhs,temp,exponent,checkY;
    auto* const p=&curve.group.MBEDTLS_PRIVATE(P);
    auto* const b=&curve.group.MBEDTLS_PRIVATE(B);
    int rc=mbedtls_mpi_read_binary(&x.v,packed.data()+1,32);
    if(rc==0)rc=mbedtls_mpi_cmp_mpi(&x.v,p)<0?0:-1;
    if(rc==0)rc=mbedtls_mpi_mul_mpi(&rhs.v,&x.v,&x.v);
    if(rc==0)rc=mbedtls_mpi_mod_mpi(&rhs.v,&rhs.v,p);
    if(rc==0)rc=mbedtls_mpi_mul_mpi(&rhs.v,&rhs.v,&x.v);
    if(rc==0)rc=mbedtls_mpi_mod_mpi(&rhs.v,&rhs.v,p);
    if(rc==0)rc=mbedtls_mpi_mul_int(&temp.v,&x.v,3);
    if(rc==0)rc=mbedtls_mpi_sub_mpi(&rhs.v,&rhs.v,&temp.v);
    if(rc==0)rc=mbedtls_mpi_add_mpi(&rhs.v,&rhs.v,b);
    if(rc==0)rc=mbedtls_mpi_mod_mpi(&rhs.v,&rhs.v,p);
    if(rc==0)rc=mbedtls_mpi_add_int(&exponent.v,p,1);
    if(rc==0)rc=mbedtls_mpi_div_int(&exponent.v,nullptr,&exponent.v,4);
    if(rc==0)rc=mbedtls_mpi_exp_mod(&y.v,&rhs.v,&exponent.v,p,nullptr);
    if(rc==0)rc=mbedtls_mpi_mul_mpi(&checkY.v,&y.v,&y.v);
    if(rc==0)rc=mbedtls_mpi_mod_mpi(&checkY.v,&checkY.v,p);
    if(rc==0)rc=mbedtls_mpi_cmp_mpi(&checkY.v,&rhs.v)==0?0:-1;
    if(rc==0&&mbedtls_mpi_get_bit(&y.v,0)!=(packed[0]&1))
        rc=mbedtls_mpi_sub_mpi(&y.v,p,&y.v);
    if(rc==0)rc=mbedtls_mpi_copy(&q.q.MBEDTLS_PRIVATE(X),&x.v);
    if(rc==0)rc=mbedtls_mpi_copy(&q.q.MBEDTLS_PRIVATE(Y),&y.v);
    if(rc==0)rc=mbedtls_mpi_lset(&q.q.MBEDTLS_PRIVATE(Z),1);
    if(rc==0)rc=mbedtls_ecp_check_pubkey(&curve.group,&q.q);
    need(rc==0,"NPV_INVALID_PUBLIC_POINT");
}
inline void signature(const Bytes& all,const Bytes& packed){
    need(all.size()>=64,"NPV_TRUNCATED_SIGNATURE");
    Curve curve;Point q;pointRead(curve,q,packed);
    Bytes signedPart(all.begin(),all.end()-64);
    const Bytes digest=hash(signedPart);
    Mpi r,s;
    int rc=mbedtls_mpi_read_binary(&r.v,all.data()+all.size()-64,32);
    if(rc==0)rc=mbedtls_mpi_read_binary(&s.v,all.data()+all.size()-32,32);
    if(rc==0)rc=mbedtls_ecdsa_verify(&curve.group,digest.data(),digest.size(),
                                     &q.q,&r.v,&s.v);
    need(rc==0,"NPV_INVALID_SIGNATURE");
}
inline Bytes shared(const Bytes& privateDer,const Bytes& packed){
    Curve curve;Point ephemeral,result;pointRead(curve,ephemeral,packed);
    struct Rng{
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context drbg;
        Rng(){
            mbedtls_entropy_init(&entropy);mbedtls_ctr_drbg_init(&drbg);
            const unsigned char label[]="SP-DECODE-NPV-RECIPIENT";
            need(mbedtls_ctr_drbg_seed(&drbg,mbedtls_entropy_func,&entropy,label,sizeof(label)-1)==0,
                 "NPV_RANDOM_FAILED");
        }
        ~Rng(){mbedtls_ctr_drbg_free(&drbg);mbedtls_entropy_free(&entropy);}
    } rng;
    mbedtls_pk_context pk;mbedtls_pk_init(&pk);
    int rc=mbedtls_pk_parse_key(&pk,privateDer.data(),privateDer.size(),
                               nullptr,0,mbedtls_ctr_drbg_random,&rng.drbg);
    if(rc!=0){mbedtls_pk_free(&pk);throw Error("NPV_INVALID_PRIVATE_KEY");}
    auto* key=mbedtls_pk_ec(pk);
    need(key!=nullptr,"NPV_PRIVATE_NOT_EC");
    rc=mbedtls_ecp_mul(&curve.group,&result.q,
          &key->MBEDTLS_PRIVATE(d),&ephemeral.q,
          mbedtls_ctr_drbg_random,&rng.drbg);
    Bytes output(32);
    if(rc==0)rc=mbedtls_mpi_write_binary(&result.q.MBEDTLS_PRIVATE(X),
                                        output.data(),output.size());
    mbedtls_pk_free(&pk);
    need(rc==0,"NPV_ECDH_FAILED");
    return output;
}
} // namespace spdecode::offline::npv
