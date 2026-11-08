#include <jni.h>
#include "spdecode_http_custom.h"
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Bytes = std::vector<unsigned char>;
constexpr size_t kMaxInput = 4u * 1024u * 1024u;
struct Failure final : std::runtime_error {using std::runtime_error::runtime_error;};
void required(int rc){if(rc!=0)throw Failure("NATIVE_CRYPTO_FAILURE");}
struct Rng {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    Rng(){
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&drbg);
        constexpr unsigned char label[]="SP-DECODE-OFFLINE-NPV-P256";
        required(mbedtls_ctr_drbg_seed(&drbg,mbedtls_entropy_func,&entropy,label,sizeof(label)-1));
    }
    ~Rng(){mbedtls_ctr_drbg_free(&drbg);mbedtls_entropy_free(&entropy);}
    Rng(const Rng&)=delete;
    Rng& operator=(const Rng&)=delete;
};
struct Key {
    mbedtls_pk_context pk;
    Key(){mbedtls_pk_init(&pk);}
    ~Key(){mbedtls_pk_free(&pk);}
    Key(const Key&)=delete;
    Key& operator=(const Key&)=delete;
};
std::string b64Url(const unsigned char* bytes,size_t length){
    Bytes out(((length+2)/3)*4+4);
    size_t size=0;
    required(mbedtls_base64_encode(out.data(),out.size(),&size,bytes,length));
    std::string text(reinterpret_cast<const char*>(out.data()),size);
    for(char& c:text){if(c=='+')c='-';else if(c=='/')c='_';}
    while(!text.empty()&&text.back()=='=')text.pop_back();
    return text;
}
std::string hex(const unsigned char* bytes,size_t length){
    static constexpr char alphabet[]="0123456789abcdef";
    std::string out;out.reserve(length*2);
    for(size_t i=0;i<length;i++){
        out.push_back(alphabet[bytes[i]>>4]);
        out.push_back(alphabet[bytes[i]&15]);
    }
    return out;
}
void derLen(Bytes& out,size_t n){
    if(n<128)out.push_back(static_cast<unsigned char>(n));
    else if(n<256){out.push_back(0x81);out.push_back(static_cast<unsigned char>(n));}
    else if(n<65536){out.push_back(0x82);out.push_back(static_cast<unsigned char>(n>>8));out.push_back(static_cast<unsigned char>(n));}
    else throw Failure("INVALID_DER_LENGTH");
}
Bytes derTag(unsigned char tag,const Bytes& value){
    Bytes out;out.reserve(value.size()+4);
    out.push_back(tag);derLen(out,value.size());
    out.insert(out.end(),value.begin(),value.end());
    return out;
}
std::string generateP256(){
    Rng rng;
    Key key;
    required(mbedtls_pk_setup(&key.pk,mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)));
    required(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,mbedtls_pk_ec(key.pk),
                                 mbedtls_ctr_drbg_random,&rng.drbg));
    auto* curve=mbedtls_pk_ec(key.pk);
    std::array<unsigned char,65> pub{};
    size_t pubSize=0;
    required(mbedtls_ecp_point_write_binary(&curve->MBEDTLS_PRIVATE(grp),
          &curve->MBEDTLS_PRIVATE(Q),MBEDTLS_ECP_PF_COMPRESSED,
          &pubSize,pub.data(),pub.size()));
    if(pubSize!=33||(pub[0]!=2&&pub[0]!=3))throw Failure("INVALID_NPV_PUBLIC");
    std::array<unsigned char,32> fingerprint{};
    required(mbedtls_sha256(pub.data(),pubSize,fingerprint.data(),0));
    // mbedtls_pk_write_key_der emits SEC1 ECPrivateKey. The existing Python
    // recipient protocol requires PKCS#8 PrivateKeyInfo wrapping SEC1 DER.
    Bytes traditional(512,0);
    const int length=mbedtls_pk_write_key_der(&key.pk,traditional.data(),traditional.size());
    if(length<48||length>512)throw Failure("INVALID_NPV_PRIVATE");
    Bytes sec1(traditional.end()-length,traditional.end());
    std::fill(traditional.begin(),traditional.end(),0);
    static const Bytes ecAlgorithm={
        0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
        0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07
    };
    Bytes body={0x02,0x01,0x00};
    body.insert(body.end(),ecAlgorithm.begin(),ecAlgorithm.end());
    const auto secretOctet=derTag(0x04,sec1);
    body.insert(body.end(),secretOctet.begin(),secretOctet.end());
    Bytes pkcs8=derTag(0x30,body);
    const std::string json=
      "{\"schema\":\"spdecode.npvs.recipient.v1\",\"kind\":\"keypair\","
      "\"source\":\"generated\",\"curve\":\"P-256\",\"publicKey\":\""+
      b64Url(pub.data(),pubSize)+"\",\"privateKey\":\""+
      b64Url(pkcs8.data(),pkcs8.size())+"\",\"fingerprint\":\""+
      hex(fingerprint.data(),fingerprint.size())+"\"}";
    std::fill(sec1.begin(),sec1.end(),0);
    std::fill(body.begin(),body.end(),0);
    std::fill(pkcs8.begin(),pkcs8.end(),0);
    return json;
}
std::string fromJava(JNIEnv* env,jstring value){
    if(!value)throw Failure("MISSING_PARAMETER");
    const char* ptr=env->GetStringUTFChars(value,nullptr);
    if(!ptr)throw Failure("INVALID_JNI_STRING");
    std::string text(ptr);
    env->ReleaseStringUTFChars(value,ptr);
    return text;
}
Bytes fromJava(JNIEnv* env,jbyteArray value){
    if(!value)throw Failure("EMPTY_FILE");
    const jsize n=env->GetArrayLength(value);
    if(n<1||static_cast<size_t>(n)>kMaxInput)throw Failure("FILE_TOO_LARGE");
    Bytes raw(static_cast<size_t>(n));
    env->GetByteArrayRegion(value,0,n,reinterpret_cast<jbyte*>(raw.data()));
    if(env->ExceptionCheck())throw Failure("INVALID_JNI_FILE");
    return raw;
}
Bytes decodeB64(const Bytes& source){
    std::string encoded;encoded.reserve(source.size());
    for(unsigned char c:source){
        if(c==' '||c=='\r'||c=='\n'||c=='\t')continue;
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||
             c=='+'||c=='/'||c=='='))throw Failure("NETMOD_INVALID_BASE64");
        encoded.push_back(static_cast<char>(c));
    }
    if(encoded.empty()||encoded.size()>kMaxInput*2||encoded.size()%4!=0)
        throw Failure("NETMOD_INVALID_BASE64");
    Bytes out(encoded.size()*3/4+4);
    size_t size=0;
    if(mbedtls_base64_decode(out.data(),out.size(),&size,
       reinterpret_cast<const unsigned char*>(encoded.data()),encoded.size())!=0)
        throw Failure("NETMOD_INVALID_BASE64");
    out.resize(size);
    if(out.empty()||out.size()%16!=0)throw Failure("NETMOD_INVALID_AES_BLOCKS");
    return out;
}
Bytes aes128Ecb(const Bytes& ciphertext,const char* key){
    if(ciphertext.size()<16||ciphertext.size()>kMaxInput)return {};
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    Bytes plaintext(ciphertext.size());
    int rc=mbedtls_aes_setkey_dec(&aes,reinterpret_cast<const unsigned char*>(key),128);
    for(size_t n=0;rc==0&&n<ciphertext.size();n+=16)
        rc=mbedtls_aes_crypt_ecb(&aes,MBEDTLS_AES_DECRYPT,ciphertext.data()+n,plaintext.data()+n);
    mbedtls_aes_free(&aes);
    if(rc!=0)return {};
    const size_t pad=plaintext.back();
    if(pad<1||pad>16||pad>plaintext.size())return {};
    unsigned char diff=0;
    for(size_t i=0;i<pad;i++)diff|=static_cast<unsigned char>(plaintext[plaintext.size()-1-i]^pad);
    if(diff)return {};
    plaintext.resize(plaintext.size()-pad);
    return plaintext;
}
Bytes decryptNm(const Bytes& input){
    const Bytes ciphertext=decodeB64(input);
    // Exact known NetMod Syna keys and order from decoders/Python/nms.py.
    static constexpr std::array<const char*,3> keys={
        "<n3t5yn4^n3tm0d>","_netsyna_netmod_","nicetrybuddygoon"
    };
    for(const char* key:keys){
        Bytes decrypted=aes128Ecb(ciphertext,key);
        if(!decrypted.empty()&&decrypted.front()=='{'){
            return decrypted; // Full original JSON, not the lossy flattened bot view.
        }
        std::fill(decrypted.begin(),decrypted.end(),0);
    }
    throw Failure("NETMOD_AUTH_OR_PADDING_FAILED");
}
void raise(JNIEnv* env,const char* reason){
    jclass type=env->FindClass("java/lang/IllegalArgumentException");
    if(type){env->ThrowNew(type,reason);env->DeleteLocalRef(type);}
}
} // namespace

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_ghostdeveloper_spdecode_offline_NativeOffline_decodeNative(
    JNIEnv* env,jobject,jbyteArray file,jstring suffix,jstring password,jstring hwid){
    try {
        const std::string format=fromJava(env,suffix);
        Bytes source=fromJava(env,file);
        Bytes decoded;
        if(format=="hc") {
            const std::string clear=spdecode::offline::decodeHttpCustom(
                source,fromJava(env,password),fromJava(env,hwid));
            decoded.assign(clear.begin(),clear.end());
        }else if(format=="nm") {
            decoded=decryptNm(source);
        }else {
            if(format=="ehi")throw Failure("HTTP_INJECTOR_NATIVE_PARITY_PENDING");
            if(format=="npvs"||format=="npv4"||format=="npvt")
                throw Failure("NPV_NATIVE_DECRYPTION_PENDING");
            throw Failure("UNSUPPORTED_OFFLINE_FORMAT");
        }
        std::fill(source.begin(),source.end(),0);
        jbyteArray result=env->NewByteArray(static_cast<jsize>(decoded.size()));
        if(result)env->SetByteArrayRegion(result,0,static_cast<jsize>(decoded.size()),
                                          reinterpret_cast<const jbyte*>(decoded.data()));
        std::fill(decoded.begin(),decoded.end(),0);
        return result;
    } catch(const Failure& problem){raise(env,problem.what());return nullptr;}
      catch(const std::exception& error){
        const std::string kind=error.what();
        if(kind.rfind("HC_",0)==0||kind=="AUTH_FAILED"||
           kind=="PASSWORD_REQUIRED"||kind=="HWID_REQUIRED"||
           kind=="HWID_PASSWORD_REQUIRED")raise(env,kind.c_str());
        else raise(env,"NATIVE_UNEXPECTED_ERROR");
        return nullptr;
      }
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_ghostdeveloper_spdecode_offline_NativeOffline_generateIdentityNative(
    JNIEnv* env,jobject){
    try {const std::string result=generateP256();return env->NewStringUTF(result.c_str());}
    catch(const std::exception&){raise(env,"NPV_KEY_GENERATION_FAILED");return nullptr;}
}