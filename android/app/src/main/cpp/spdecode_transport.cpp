#include <jni.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "spdecode_hpke.h"
#include "spdecode_security.h"
#include "spdecode_session.h"
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <cctype>
#include <string>

#include "cloud_origin.h"

namespace {
// PUBLIC X25519 trust anchor, stored as two byte shares (no plaintext key or
// kid:base64url literal). Reversible obfuscation, NOT secret encryption.
// The server's private key must NEVER be packaged in an Android binary.
constexpr jsize kHpkePinLength=40;
volatile const unsigned char kHpkePinPartA[kHpkePinLength]={0x4d, 0xd5, 0x69, 0x60, 0xc8, 0xca, 0xdc, 0x25, 0x57, 0xad, 0x5d, 0xec, 0xab, 0x06, 0xc2, 0xd1, 0x7f, 0xdc, 0x54, 0x2f, 0x29, 0x04, 0x36, 0x1a, 0xc4, 0x11, 0x8b, 0x45, 0xda, 0xf7, 0x36, 0x6f, 0x02, 0xaa, 0x4c, 0x05, 0x79, 0xab, 0xc0, 0x14};
volatile const unsigned char kHpkePinPartB[kHpkePinLength]={0xc4, 0xba, 0x70, 0x36, 0xec, 0xeb, 0xa1, 0x67, 0xdd, 0x93, 0x92, 0x48, 0x0e, 0xc4, 0xba, 0xb9, 0x7f, 0x35, 0xeb, 0xa1, 0xa0, 0x66, 0xdc, 0x92, 0x48, 0x57, 0x0d, 0xc3, 0xb9, 0x7f, 0x7e, 0x34, 0xea, 0xa0, 0x66, 0x65, 0xdb, 0x91, 0x57, 0x0d};
std::array<unsigned char,40> nativePublicHpkePin() {
    std::array<unsigned char,40> pin{};
    for(size_t i=0;i<pin.size();++i)
        pin[i]=static_cast<unsigned char>(kHpkePinPartA[i]^kHpkePinPartB[i]);
    return pin;
}

constexpr size_t kMaxRequestBytes = 12 * 1024 * 1024;
constexpr size_t kMaxReplyBytes = 6 * 1024 * 1024;
// Server-VPN MKK only: the signed JSON envelope carries both raw and structured data.
constexpr size_t kMaxMkkReplyBytes = 96 * 1024 * 1024;
constexpr jint kConnectTimeoutMs = 10000;
constexpr jint kReadTimeoutMs = 25000;
constexpr jint kNurCatalogReadTimeoutMs = 165000; // heavy server-side Argon2id

std::string utf(JNIEnv* env, jstring value) {
    if (value == nullptr) return {};
    const char* chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) return {};
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    return result;
}
void fail(JNIEnv* env, const char* message) {
    if (env->ExceptionCheck()) env->ExceptionClear();
    const jclass io = env->FindClass("java/io/IOException");
    if (io != nullptr) env->ThrowNew(io, message);
}
bool clearException(JNIEnv* env) {
    if (!env->ExceptionCheck()) return false;
    env->ExceptionClear();
    return true;
}
bool safeBase(const std::string& value) {
    // Build-time injected origin only, not a user-supplied import destination.
    const std::string scheme = "https://";
    if (value.size() < scheme.size() + 4 || value.size() > 256 ||
        value.compare(0,scheme.size(),scheme) != 0) return false;
    const auto host = value.substr(scheme.size());
    if (host.front()=='.' || host.back()=='.' || host.find('.')==std::string::npos ||
        host.find("..")!=std::string::npos) return false;
    if (host == "localhost" || (host.size() >= 6 && host.compare(host.size()-6,6,".local")==0))
        return false;
    if (!std::all_of(host.begin(),host.end(),[](unsigned char c){
        return std::isalnum(c) || c == '.' || c == '-';
    })) return false;
    if (std::all_of(host.begin(),host.end(),[](unsigned char c){
        return std::isdigit(c) || c == '.';
    })) return false;
    return true;
}
bool safeOperation(jint operation) { return operation>=1 && operation<=17 && operation!=3; }
bool safeProof(const std::string& value,size_t min,size_t max) {
    return value.size()>=min && value.size()<=max &&
        std::all_of(value.begin(),value.end(),[](unsigned char c){
            return std::isalnum(c) || c=='-' || c=='_';
        });
}
bool safeBearer(const std::string& token) {
    if (token.size()>2048) return false;
    return std::all_of(token.begin(),token.end(),[](unsigned char c) {
        return std::isalnum(c) || c == '-' || c == '_' || c == '.';
    });
}
jstring jstr(JNIEnv* env,const char* s) {return env->NewStringUTF(s);}
bool setHeader(JNIEnv* env,jobject conn,jclass cls,jmethodID method,
               const char* name,const std::string& value) {
    (void)cls;
    jstring key = jstr(env,name);
    jstring val = env->NewStringUTF(value.c_str());
    if (key==nullptr || val==nullptr)return false;
    env->CallVoidMethod(conn,method,key,val);
    env->DeleteLocalRef(key);
    env->DeleteLocalRef(val);
    return !env->ExceptionCheck();
}
bool setHeader(JNIEnv* env,jobject conn,jclass cls,jmethodID method,
               const char* name,const char* value) {
    (void)cls;
    return setHeader(env,conn,cls,method,name,std::string(value));
}

// C++ owns network initiation, route verification, HTTP method, request headers,
// size limits and reading. Android's HttpsURLConnection provides platform TLS
// certificate/hostname verification; certificate validation is never disabled.
jbyteArray post(JNIEnv* env,jclass,jint operation,jbyteArray bodyArg,jstring bearerArg,jstring versionArg,
             jstring timestampArg,jstring nonceArg,jstring proofArg,jstring actionChallengeArg,jstring actionIntegrityArg) {
    const std::string base=cloudOrigin();
    const std::string path=cloudTransportPath();
    const std::string timestamp=utf(env,timestampArg);
    const std::string nonce=utf(env,nonceArg);
    const std::string proof=utf(env,proofArg);
    const std::string actionChallenge=utf(env,actionChallengeArg);
    const std::string actionIntegrity=utf(env,actionIntegrityArg);
    const jsize bodySize=bodyArg ? env->GetArrayLength(bodyArg) : 0;
    const std::string bearer=utf(env,bearerArg);
    const std::string clientVersion=utf(env,versionArg);
    const bool validVersion=clientVersion.size()>=5 && clientVersion.size()<=11 &&
        std::all_of(clientVersion.begin(),clientVersion.end(),[](unsigned char c){
            return std::isdigit(c) || c=='.';
        }) && std::count(clientVersion.begin(),clientVersion.end(),'.')==2;
    if (!validVersion || !safeBase(base) || !safeOperation(operation) ||
        timestamp.size()<10 || timestamp.size()>11 ||
        !std::all_of(timestamp.begin(),timestamp.end(),[](unsigned char c){return std::isdigit(c);}) ||
        !safeProof(nonce,32,32) || !safeProof(proof,90,100) || !safeBearer(bearer) ||
        (!actionChallenge.empty() && (actionChallenge.size()!=36 ||
            !std::all_of(actionChallenge.begin(),actionChallenge.end(),[](unsigned char c){return std::isxdigit(c)||c=='-';}))) ||
        (!actionIntegrity.empty() && (actionIntegrity.size()<80 || actionIntegrity.size()>16384 ||
            !std::all_of(actionIntegrity.begin(),actionIntegrity.end(),[](unsigned char c){return c>=0x21 && c<=0x7e;}))) ||
        actionChallenge.empty()!=actionIntegrity.empty() || bodySize<=0 || static_cast<size_t>(bodySize)>kMaxRequestBytes) {
        fail(env,"CLOUD_NATIVE_REQUEST_REJECTED");return nullptr;
    }
    jclass urlClass = env->FindClass("java/net/URL");
    jclass connectionClass=env->FindClass("java/net/URLConnection");
    jclass httpClass=env->FindClass("java/net/HttpURLConnection");
    jclass httpsClass=env->FindClass("javax/net/ssl/HttpsURLConnection");
    jclass streamClass=env->FindClass("java/io/InputStream");
    jclass outputClass=env->FindClass("java/io/OutputStream");
    if (!urlClass || !connectionClass || !httpClass || !httpsClass ||
        !streamClass || !outputClass) {
        fail(env,"CLOUD_NATIVE_JNI_UNAVAILABLE");return nullptr;
    }
    const jmethodID urlCtor=env->GetMethodID(urlClass,"<init>","(Ljava/lang/String;)V");
    const jmethodID open=env->GetMethodID(urlClass,"openConnection","()Ljava/net/URLConnection;");
    const jmethodID setMethod=env->GetMethodID(httpClass,"setRequestMethod","(Ljava/lang/String;)V");
    const jmethodID setRedirect=env->GetMethodID(httpClass,"setInstanceFollowRedirects","(Z)V");
    const jmethodID setConnect=env->GetMethodID(connectionClass,"setConnectTimeout","(I)V");
    const jmethodID setRead=env->GetMethodID(connectionClass,"setReadTimeout","(I)V");
    const jmethodID setOutput=env->GetMethodID(connectionClass,"setDoOutput","(Z)V");
    const jmethodID setProperty=env->GetMethodID(connectionClass,"setRequestProperty","(Ljava/lang/String;Ljava/lang/String;)V");
    const jmethodID setLength=env->GetMethodID(httpClass,"setChunkedStreamingMode","(I)V");
    const jmethodID getOutput=env->GetMethodID(connectionClass,"getOutputStream","()Ljava/io/OutputStream;");
    const jmethodID getInput=env->GetMethodID(connectionClass,"getInputStream","()Ljava/io/InputStream;");
    const jmethodID getError=env->GetMethodID(httpClass,"getErrorStream","()Ljava/io/InputStream;");
    const jmethodID statusMethod=env->GetMethodID(httpClass,"getResponseCode","()I");
    const jmethodID disconnect=env->GetMethodID(httpClass,"disconnect","()V");
    const jmethodID write=env->GetMethodID(outputClass,"write","([B)V");
    const jmethodID closeOutput=env->GetMethodID(outputClass,"close","()V");
    const jmethodID read=env->GetMethodID(streamClass,"read","([BII)I");
    const jmethodID closeInput=env->GetMethodID(streamClass,"close","()V");
    if (!urlCtor || !open || !setMethod || !setRedirect || !setConnect ||
        !setRead || !setOutput || !setProperty || !setLength ||
        !getOutput || !getInput || !getError || !statusMethod || !disconnect ||
        !write || !closeOutput || !read || !closeInput) {
        fail(env,"CLOUD_NATIVE_METHOD_UNAVAILABLE");return nullptr;
    }

    jstring urlString=env->NewStringUTF((base+path).c_str());
    jobject url=env->NewObject(urlClass,urlCtor,urlString);
    env->DeleteLocalRef(urlString);
    if (clearException(env) || !url) {
        fail(env,"CLOUD_NATIVE_URL_REJECTED");return nullptr;
    }
    jobject conn=env->CallObjectMethod(url,open);
    env->DeleteLocalRef(url);
    if (clearException(env) || !conn) {
        fail(env,"CLOUD_NATIVE_CONNECT_FAILED");return nullptr;
    }
    if (!env->IsInstanceOf(conn,httpsClass)) {
        env->DeleteLocalRef(conn);
        fail(env,"CLOUD_NATIVE_TLS_REQUIRED");return nullptr;
    }
    jstring method=jstr(env,"POST");
    env->CallVoidMethod(conn,setMethod,method);
    bool ok=!env->ExceptionCheck();
    env->DeleteLocalRef(method);
    if(ok){env->CallVoidMethod(conn,setRedirect,JNI_FALSE);ok=!env->ExceptionCheck();}
    if(ok){env->CallVoidMethod(conn,setConnect,kConnectTimeoutMs);ok=!env->ExceptionCheck();}
    // Do not relax ordinary decoder/session timeouts. NUR server catalog
    // can require up to 120s on the remote worker for nested Argon2id fields.
    const jint readTimeout = (operation == 9 || operation == 12) ?
        kNurCatalogReadTimeoutMs : (operation == 5 ? 55000 : kReadTimeoutMs);
    if(ok){env->CallVoidMethod(conn,setRead,readTimeout);ok=!env->ExceptionCheck();}
    if(ok){env->CallVoidMethod(conn,setOutput,JNI_TRUE);ok=!env->ExceptionCheck();}
    if(ok){env->CallVoidMethod(conn,setLength,8192);ok=!env->ExceptionCheck();}
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"Content-Type","application/octet-stream");
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"Accept","application/octet-stream");
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"Accept-Encoding","identity");
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"Cache-Control","no-store");
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"X-SPDecode-App-Version",clientVersion);
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"X-SP-Operation",std::to_string(operation));
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"X-SP-Timestamp",timestamp);
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"X-SP-Nonce",nonce);
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"X-SP-Proof",proof);
    if(ok && !actionChallenge.empty())ok=setHeader(env,conn,connectionClass,setProperty,"X-SP-Action-Challenge",actionChallenge);
    if(ok && !actionIntegrity.empty())ok=setHeader(env,conn,connectionClass,setProperty,"X-SP-Action-Integrity",actionIntegrity);
    // Capability negotiation for the new credential dialog. Older APKs omit
    // this header automatically. It is not trusted for authentication.
    if(ok && (operation == 5 || operation == 6))
        ok=setHeader(env,conn,connectionClass,setProperty,"X-SPDecode-Credential-Prompts","1");
    if(ok && operation == 10)
        ok=setHeader(env,conn,connectionClass,setProperty,"X-SPDecode-NPV-Identities","1");
    if(ok && (operation == 5 || operation == 10 || operation == 13))
        ok=setHeader(env,conn,connectionClass,setProperty,"X-SPDecode-Compatible-Export","1");
    if(ok && !bearer.empty())ok=setHeader(env,conn,connectionClass,setProperty,"Authorization","Bearer "+bearer);
    if(!ok) {
        clearException(env);env->CallVoidMethod(conn,disconnect);
        env->DeleteLocalRef(conn);
        fail(env,"CLOUD_NATIVE_HEADERS_FAILED");return nullptr;
    }
    jobject os=env->CallObjectMethod(conn,getOutput);
    if(clearException(env) || !os) {
        env->CallVoidMethod(conn,disconnect);env->DeleteLocalRef(conn);
        fail(env,"CLOUD_NATIVE_NETWORK_UNAVAILABLE");return nullptr;
    }
    if(bodyArg && !env->ExceptionCheck())env->CallVoidMethod(os,write,bodyArg);
    if(!env->ExceptionCheck())env->CallVoidMethod(os,closeOutput);
    env->DeleteLocalRef(os);
    if(clearException(env)) {
        env->CallVoidMethod(conn,disconnect);env->DeleteLocalRef(conn);
        fail(env,"CLOUD_NATIVE_UPLOAD_FAILED");return nullptr;
    }
    const jint status=env->CallIntMethod(conn,statusMethod);
    if(clearException(env) || status<100 || status>599) {
        env->CallVoidMethod(conn,disconnect);env->DeleteLocalRef(conn);
        fail(env,"CLOUD_NATIVE_RESPONSE_UNAVAILABLE");return nullptr;
    }
    jobject input=status>=400?env->CallObjectMethod(conn,getError):env->CallObjectMethod(conn,getInput);
    if(clearException(env) || input==nullptr) {
        env->CallVoidMethod(conn,disconnect);env->DeleteLocalRef(conn);
        fail(env,"CLOUD_NATIVE_EMPTY_RESPONSE");return nullptr;
    }
    jbyteArray buffer=env->NewByteArray(8192);
    std::string result;
    const size_t replyCap=operation==12 ? kMaxMkkReplyBytes :
        (operation==8 ? 12U*1024U*1024U : kMaxReplyBytes);
    bool oversize=false,readFailed=false;
    for(;;) {
        const jint n=env->CallIntMethod(input,read,buffer,0,8192);
        if(clearException(env)){readFailed=true;break;}
        if(n<0)break;
        if(n==0)continue;
        if(result.size()+static_cast<size_t>(n)>replyCap){oversize=true;break;}
        const size_t offset=result.size();
        result.resize(offset+static_cast<size_t>(n));
        env->GetByteArrayRegion(buffer,0,n,reinterpret_cast<jbyte*>(&result[offset]));
        if(clearException(env)){readFailed=true;break;}
    }
    env->CallVoidMethod(input,closeInput);
    clearException(env);
    env->CallVoidMethod(conn,disconnect);
    clearException(env);
    env->DeleteLocalRef(buffer);
    env->DeleteLocalRef(input);
    env->DeleteLocalRef(conn);
    if(readFailed || oversize || result.empty()) {
        fail(env,oversize?"CLOUD_NATIVE_RESPONSE_TOO_LARGE":"CLOUD_NATIVE_READ_FAILED");
        return nullptr;
    }
    // The response body is a complete JSON document; Kotlin validates it.
    const std::string envelope=std::to_string(status)+"\n"+result;
    jbyteArray raw=env->NewByteArray(static_cast<jsize>(envelope.size()));
    if(raw==nullptr){fail(env,"CLOUD_NATIVE_RESPONSE_MEMORY");return nullptr;}
    env->SetByteArrayRegion(raw,0,static_cast<jsize>(envelope.size()),
                            reinterpret_cast<const jbyte*>(envelope.data()));
    if(clearException(env)){fail(env,"CLOUD_NATIVE_RESPONSE_MEMORY");return nullptr;}
    return raw;
}
}

// The native boundary owns HPKE key agreement, HKDF, AEAD, wire framing and
// decrypted response verification. No derived cryptographic key is passed
// through Java/Kotlin. Android services (Keystore, Play, TLS) retain JNI access.
namespace {
struct ScrubOnExit {
    std::vector<unsigned char>& bytes;
    ~ScrubOnExit(){
        if(!bytes.empty())mbedtls_platform_zeroize(bytes.data(),bytes.size());
    }
};
std::vector<unsigned char> nativeRead(JNIEnv* env,jbyteArray input,size_t limit) {
    if(input==nullptr)return {};
    const jsize length=env->GetArrayLength(input);
    if(length<0||static_cast<size_t>(length)>limit)
        throw std::runtime_error("CLOUD_HPKE_NATIVE_INPUT");
    std::vector<unsigned char> bytes(static_cast<size_t>(length));
    if(length>0)env->GetByteArrayRegion(input,0,length,
        reinterpret_cast<jbyte*>(bytes.data()));
    if(env->ExceptionCheck())throw std::runtime_error("CLOUD_HPKE_NATIVE_INPUT");
    return bytes;
}
jbyteArray nativeWrite(JNIEnv* env,const std::vector<unsigned char>& bytes){
    if(bytes.size()>static_cast<size_t>(INT32_MAX))
        throw std::runtime_error("CLOUD_HPKE_NATIVE_SIZE");
    jbyteArray result=env->NewByteArray(static_cast<jsize>(bytes.size()));
    if(result!=nullptr&&!bytes.empty())
        env->SetByteArrayRegion(result,0,static_cast<jsize>(bytes.size()),
                                reinterpret_cast<const jbyte*>(bytes.data()));
    return result;
}
jbyteArray prepareHpke(JNIEnv* env,jclass,jint operation,
                       jbyteArray metadataArg,jbyteArray attachmentArg){
    try{
        if(metadataArg==nullptr)throw std::runtime_error("CLOUD_HPKE_METADATA_MISSING");
        auto metadata=nativeRead(env,metadataArg,1024U*1024U);
        ScrubOnExit scrubMetadata{metadata};
        auto attachment=nativeRead(env,attachmentArg,8U*1024U*1024U);
        ScrubOnExit scrubAttachment{attachment};
        auto prepared=spdecode::hpkePrepare(operation,metadata,attachment,nativePublicHpkePin());
        std::vector<unsigned char> result;
        result.reserve(8+prepared.wire.size());
        for(int shift=56;shift>=0;shift-=8)
            result.push_back(static_cast<unsigned char>(prepared.handle>>shift));
        result.insert(result.end(),prepared.wire.begin(),prepared.wire.end());
        jbyteArray encoded=nativeWrite(env,result);
        if(encoded==nullptr||env->ExceptionCheck()){
            spdecode::hpkeDiscard(prepared.handle);
            fail(env,"CLOUD_HPKE_NATIVE_MEMORY");return nullptr;
        }
        return encoded;
    }catch(const std::exception&){
        fail(env,"CLOUD_HPKE_ENCRYPT_FAILED");return nullptr;
    }
}
jbyteArray openHpke(JNIEnv* env,jclass,jlong stateHandle,jint status,
                    jbyteArray wireArg,jbyteArray responseArg){
    const auto handle=static_cast<std::uint64_t>(stateHandle);
    try{
        if(wireArg==nullptr||responseArg==nullptr)
            throw std::runtime_error("CLOUD_HPKE_REPLY_INVALID");
        auto wire=nativeRead(env,wireArg,11U*1024U*1024U);
        auto reply=nativeRead(env,responseArg,96U*1024U*1024U+27+16);
        auto clear=spdecode::hpkeOpen(handle,status,wire,reply);
        ScrubOnExit scrubClear{clear};
        jbyteArray result=nativeWrite(env,clear);
        if(result==nullptr||env->ExceptionCheck()){
            fail(env,"CLOUD_HPKE_NATIVE_MEMORY");return nullptr;
        }
        return result;
    }catch(const std::exception&){
        spdecode::hpkeDiscard(handle);
        fail(env,"CLOUD_HPKE_REPLY_INVALID");return nullptr;
    }
}
void discardHpke(JNIEnv*,jclass,jlong stateHandle){
    spdecode::hpkeDiscard(static_cast<std::uint64_t>(stateHandle));
}
}

// Native proof serialization. Actual P-256 private-key signing remains in
// Android Keystore; its key material never leaves the platform.
namespace {
jstring nativePlayNonce(JNIEnv* env,jclass,jstring nonce,jstring id,jstring publicKey) {
    try {
        const auto value=spdecode::playNonce(utf(env,nonce),utf(env,id),utf(env,publicKey));
        return env->NewStringUTF(value.c_str());
    }catch(const std::exception&){fail(env,"CLOUD_NATIVE_NONCE_INVALID");return nullptr;}
}
jstring nativeHashWire(JNIEnv* env,jclass,jbyteArray body){
    try {
        if(body==nullptr)throw std::runtime_error("missing");
        const auto data=nativeRead(env,body,kMaxRequestBytes);
        const auto text=spdecode::sha256Hex(data.data(),data.size());
        return env->NewStringUTF(text.c_str());
    }catch(const std::exception&){fail(env,"CLOUD_NATIVE_HASH_FAILED");return nullptr;}
}
jstring nativeFormatProof(JNIEnv* env,jclass,jint op,jstring ver,jbyteArray body,
                         jstring bearer,jstring stamp,jstring nonce){
    try {
        if(body==nullptr)throw std::runtime_error("missing");
        auto bytes=nativeRead(env,body,kMaxRequestBytes);
        ScrubOnExit scrub{bytes};
        const auto output=spdecode::formatProof(op,utf(env,ver),bytes.data(),
                          bytes.size(),utf(env,bearer),utf(env,stamp),utf(env,nonce));
        return env->NewStringUTF(output.c_str());
    }catch(const std::exception&){fail(env,"CLOUD_NATIVE_PROOF_INVALID");return nullptr;}
}
jobjectArray nativePrepareProof(JNIEnv* env,jclass,jint op,jstring ver,jbyteArray body,
                                jstring bearer) {
    try {
        if(body==nullptr)throw std::runtime_error("missing");
        auto bytes=nativeRead(env,body,kMaxRequestBytes);
        ScrubOnExit scrub{bytes};
        const auto proof=spdecode::prepareProof(op,utf(env,ver),bytes.data(),
                                               bytes.size(),utf(env,bearer));
        const jclass stringClass=env->FindClass("java/lang/String");
        if(!stringClass||env->ExceptionCheck())throw std::runtime_error("String");
        jobjectArray array=env->NewObjectArray(3,stringClass,nullptr);
        if(!array||env->ExceptionCheck())throw std::runtime_error("array");
        const std::array<std::string,3> parts={proof.timestamp,proof.nonce,proof.message};
        for(int i=0;i<3;++i) {
            jstring element=env->NewStringUTF(parts[i].c_str());
            if(!element||env->ExceptionCheck())throw std::runtime_error("element");
            env->SetObjectArrayElement(array,i,element);
            env->DeleteLocalRef(element);
            if(env->ExceptionCheck())throw std::runtime_error("set");
        }
        return array;
    }catch(const std::exception&){fail(env,"CLOUD_NATIVE_PROOF_INVALID");return nullptr;}
}
}

// Operate Android's non-exportable P-256 signing key via official JCA,
// but keep app-specific algorithm selection and call graph inside JNI.
namespace {
jbyteArray signHardwareProof(JNIEnv* env,jclass,jobject privateKey,jbyteArray message){
    if(privateKey==nullptr||message==nullptr){fail(env,"CLOUD_NATIVE_SIGN_FAILED");return nullptr;}
    const jsize length=env->GetArrayLength(message);
    if(length<80||length>4096){fail(env,"CLOUD_NATIVE_SIGN_FAILED");return nullptr;}
    jclass signatureClass=env->FindClass("java/security/Signature");
    if(signatureClass==nullptr||env->ExceptionCheck()){
        fail(env,"CLOUD_NATIVE_SIGN_FAILED");return nullptr;
    }
    const jmethodID factory=env->GetStaticMethodID(signatureClass,"getInstance",
        "(Ljava/lang/String;)Ljava/security/Signature;");
    const jmethodID init=env->GetMethodID(signatureClass,"initSign",
        "(Ljava/security/PrivateKey;)V");
    const jmethodID update=env->GetMethodID(signatureClass,"update","([B)V");
    const jmethodID sign=env->GetMethodID(signatureClass,"sign","()[B");
    if(!factory||!init||!update||!sign||env->ExceptionCheck()){
        fail(env,"CLOUD_NATIVE_SIGN_FAILED");return nullptr;
    }
    jstring algorithm=env->NewStringUTF("SHA256withECDSA");
    if(algorithm==nullptr||env->ExceptionCheck()){
        fail(env,"CLOUD_NATIVE_SIGN_FAILED");return nullptr;
    }
    jobject provider=env->CallStaticObjectMethod(signatureClass,factory,algorithm);
    env->DeleteLocalRef(algorithm);
    if(provider==nullptr||env->ExceptionCheck()){
        fail(env,"CLOUD_NATIVE_SIGN_FAILED");return nullptr;
    }
    env->CallVoidMethod(provider,init,privateKey);
    if(!env->ExceptionCheck())env->CallVoidMethod(provider,update,message);
    auto signature=env->ExceptionCheck()?nullptr:
        static_cast<jbyteArray>(env->CallObjectMethod(provider,sign));
    env->DeleteLocalRef(provider);
    if(!signature||env->ExceptionCheck()){
        fail(env,"CLOUD_NATIVE_SIGN_FAILED");return nullptr;
    }
    const jsize size=env->GetArrayLength(signature);
    if(size<64||size>80){
        env->DeleteLocalRef(signature);
        fail(env,"CLOUD_NATIVE_SIGN_FAILED");return nullptr;
    }
    return signature;
}
jstring nativeAliasSuffix(JNIEnv* env,jclass){
    try{
        const auto suffix=spdecode::makeAliasSuffix();
        return env->NewStringUTF(suffix.c_str());
    }catch(const std::exception&){
        fail(env,"CLOUD_NATIVE_RANDOM_FAILED");return nullptr;
    }
}
}

// Verify release signer with Android's PackageManager, without Java/Kotlin
// policy branches. This is defense in depth, not the admission authority.
namespace {
bool parseFingerprint(const std::string& raw,std::array<unsigned char,32>& out){
    if(raw.size()!=64)return false;
    const auto value=[](char c)->int {
        if(c>='0'&&c<='9')return c-'0';
        if(c>='a'&&c<='f')return c-'a'+10;
        if(c>='A'&&c<='F')return c-'A'+10;
        return -1;
    };
    for(size_t i=0;i<32;++i){
        int a=value(raw[i*2]),b=value(raw[i*2+1]);
        if(a<0||b<0)return false;
        out[i]=static_cast<unsigned char>((a<<4)|b);
    }
    return true;
}
jboolean verifyReleaseSigner(JNIEnv* env,jclass,jobject context,
                            jstring packageExpected,jstring uploadDigest,
                            jstring playDigest,jboolean debugBuild) {
    if(debugBuild==JNI_TRUE)return JNI_TRUE; // Preserve debug build semantics.
    if(context==nullptr)return JNI_FALSE;
    try{
        const std::string expected=utf(env,packageExpected);
        if(expected.empty())return JNI_FALSE;
        std::vector<std::array<unsigned char,32>> fingerprints;
        for(jstring digest:{uploadDigest,playDigest}){
            const std::string source=utf(env,digest);
            std::array<unsigned char,32> parsed{};
            if(parseFingerprint(source,parsed) &&
               std::find(fingerprints.begin(),fingerprints.end(),parsed)==fingerprints.end())
                fingerprints.push_back(parsed);
        }
        if(fingerprints.empty()||env->ExceptionCheck())return JNI_FALSE;
        jclass ctxClass=env->FindClass("android/content/Context");
        const jmethodID getName=env->GetMethodID(ctxClass,"getPackageName","()Ljava/lang/String;");
        const jmethodID getInfo=env->GetMethodID(ctxClass,"getApplicationInfo",
                                              "()Landroid/content/pm/ApplicationInfo;");
        const jmethodID getPm=env->GetMethodID(ctxClass,"getPackageManager",
                                             "()Landroid/content/pm/PackageManager;");
        if(!getName||!getInfo||!getPm||env->ExceptionCheck())return JNI_FALSE;
        auto name=static_cast<jstring>(env->CallObjectMethod(context,getName));
        if(!name||env->ExceptionCheck()||utf(env,name)!=expected)return JNI_FALSE;
        auto info=env->CallObjectMethod(context,getInfo);
        jclass infoClass=env->FindClass("android/content/pm/ApplicationInfo");
        const jfieldID flagsField=env->GetFieldID(infoClass,"flags","I");
        if(!info||!flagsField||env->ExceptionCheck()||
           (env->GetIntField(info,flagsField)&2)!=0)return JNI_FALSE;
        jclass debugClass=env->FindClass("android/os/Debug");
        const jmethodID connected=env->GetStaticMethodID(debugClass,"isDebuggerConnected","()Z");
        const jmethodID waiting=env->GetStaticMethodID(debugClass,"waitingForDebugger","()Z");
        if(!connected||!waiting||env->ExceptionCheck()||
           env->CallStaticBooleanMethod(debugClass,connected)==JNI_TRUE||
           env->CallStaticBooleanMethod(debugClass,waiting)==JNI_TRUE||
           env->ExceptionCheck())return JNI_FALSE;
        auto pm=env->CallObjectMethod(context,getPm);
        if(!pm||env->ExceptionCheck())return JNI_FALSE;
        jclass version=env->FindClass("android/os/Build$VERSION");
        const jfieldID sdkField=env->GetStaticFieldID(version,"SDK_INT","I");
        if(!sdkField||env->ExceptionCheck())return JNI_FALSE;
        const jint sdk=env->GetStaticIntField(version,sdkField);
        jclass pmClass=env->FindClass("android/content/pm/PackageManager");
        if(sdk>=28){
            const jmethodID hasCert=env->GetMethodID(pmClass,"hasSigningCertificate",
                                         "(Ljava/lang/String;[BI)Z");
            if(!hasCert||env->ExceptionCheck())return JNI_FALSE;
            for(const auto& digest:fingerprints){
                auto value=env->NewByteArray(32);
                if(value==nullptr||env->ExceptionCheck())return JNI_FALSE;
                env->SetByteArrayRegion(value,0,32,
                                     reinterpret_cast<const jbyte*>(digest.data()));
                if(env->ExceptionCheck())return JNI_FALSE;
                const auto match=env->CallBooleanMethod(pm,hasCert,name,value,1);
                env->DeleteLocalRef(value);
                if(env->ExceptionCheck())return JNI_FALSE;
                if(match==JNI_TRUE)return JNI_TRUE;
            }
            return JNI_FALSE;
        }
        // Legacy API 24..27: match the single real signing certificate.
        const jmethodID getPackage=env->GetMethodID(pmClass,"getPackageInfo",
                                               "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
        if(!getPackage||env->ExceptionCheck())return JNI_FALSE;
        auto infoOld=env->CallObjectMethod(pm,getPackage,name,64);
        if(!infoOld||env->ExceptionCheck())return JNI_FALSE;
        auto infoOldClass=env->FindClass("android/content/pm/PackageInfo");
        const jfieldID signatures=env->GetFieldID(infoOldClass,"signatures",
                                               "[Landroid/content/pm/Signature;");
        if(!signatures||env->ExceptionCheck())return JNI_FALSE;
        auto certs=static_cast<jobjectArray>(env->GetObjectField(infoOld,signatures));
        if(!certs||env->ExceptionCheck()||env->GetArrayLength(certs)!=1)return JNI_FALSE;
        jclass signatureClass=env->FindClass("android/content/pm/Signature");
        const jmethodID toBytes=env->GetMethodID(signatureClass,"toByteArray","()[B");
        auto signature=env->GetObjectArrayElement(certs,0);
        auto data=static_cast<jbyteArray>(env->CallObjectMethod(signature,toBytes));
        if(!data||env->ExceptionCheck())return JNI_FALSE;
        const jsize count=env->GetArrayLength(data);
        if(count<=0||count>16384)return JNI_FALSE;
        std::vector<unsigned char> encoded(static_cast<size_t>(count));
        env->GetByteArrayRegion(data,0,count,
                                reinterpret_cast<jbyte*>(encoded.data()));
        if(env->ExceptionCheck())return JNI_FALSE;
        std::array<unsigned char,32> result{};
        if(mbedtls_sha256(encoded.data(),encoded.size(),result.data(),0)!=0)
            return JNI_FALSE;
        for(const auto& fingerprint:fingerprints)
            if(result==fingerprint)return JNI_TRUE;
        return JNI_FALSE;
    }catch(const std::exception&) {
        if(env->ExceptionCheck())env->ExceptionClear();
        return JNI_FALSE;
    }
}
}

// C++ stores session state in process memory; Android receives temporary copies.
namespace {
struct ScrubString {
    std::string& value;
    ~ScrubString(){
        if(!value.empty())mbedtls_platform_zeroize(value.data(),value.size());
    }
};
void nativeCacheSession(JNIEnv* env,jclass,jstring bearerArg,jlong ttl,jboolean action){
    if(!bearerArg){fail(env,"CLOUD_INVALID_SESSION");return;}
    auto bearer=utf(env,bearerArg);
    ScrubString scrub{bearer};
    try {
        spdecode::sharedSession().store(bearer,static_cast<std::int64_t>(ttl),action==JNI_TRUE);
    }catch(const std::exception&){fail(env,"CLOUD_INVALID_SESSION");}
}
jstring nativeGetSession(JNIEnv* env,jclass){
    auto bearer=spdecode::sharedSession().get();
    ScrubString scrub{bearer};
    return env->NewStringUTF(bearer.c_str());
}
jboolean nativeRequiresActionIntegrity(JNIEnv*,jclass){
    return spdecode::sharedSession().requiresActionIntegrity()?JNI_TRUE:JNI_FALSE;
}
void nativeClearSession(JNIEnv*,jclass){spdecode::sharedSession().clear();}
void nativeInvalidateSession(JNIEnv* env,jclass,jstring bearerArg){
    auto bearer=utf(env,bearerArg);
    ScrubString scrub{bearer};
    spdecode::sharedSession().clearIfMatches(bearer);
}
}

// Register the private bridge; export only JNI_OnLoad.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm,void*) {
    JNIEnv* env=nullptr;
    if(vm->GetEnv(reinterpret_cast<void**>(&env),JNI_VERSION_1_6)!=JNI_OK)return JNI_ERR;
    jclass bridge=env->FindClass("com/ghostdeveloper/spdecode/cloud/CloudNativeTransport");
    if(!bridge)return JNI_ERR;
    JNINativeMethod methods[]={{const_cast<char*>("postNativeEncrypted"),
        const_cast<char*>("(I[BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)[B"),
        reinterpret_cast<void*>(post)},
        {const_cast<char*>("nativePrepareHpke"),const_cast<char*>("(I[B[B)[B"),
        reinterpret_cast<void*>(prepareHpke)},
        {const_cast<char*>("nativeOpenHpke"),const_cast<char*>("(JI[B[B)[B"),
        reinterpret_cast<void*>(openHpke)},
        {const_cast<char*>("nativeDiscardHpke"),const_cast<char*>("(J)V"),
        reinterpret_cast<void*>(discardHpke)},
        {const_cast<char*>("nativePlayNonce"),
        const_cast<char*>("(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
        reinterpret_cast<void*>(nativePlayNonce)},
        {const_cast<char*>("nativeHashWire"),
        const_cast<char*>("([B)Ljava/lang/String;"),
        reinterpret_cast<void*>(nativeHashWire)},
        {const_cast<char*>("nativeFormatProof"),
        const_cast<char*>("(ILjava/lang/String;[BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
        reinterpret_cast<void*>(nativeFormatProof)},
        {const_cast<char*>("nativePrepareProof"),
        const_cast<char*>("(ILjava/lang/String;[BLjava/lang/String;)[Ljava/lang/String;"),
        reinterpret_cast<void*>(nativePrepareProof)},
        {const_cast<char*>("nativeVerifyReleaseSigner"),
        const_cast<char*>("(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Z"),
        reinterpret_cast<void*>(verifyReleaseSigner)},
        {const_cast<char*>("nativeSignHardware"),
        const_cast<char*>("(Ljava/security/PrivateKey;[B)[B"),
        reinterpret_cast<void*>(signHardwareProof)},
        {const_cast<char*>("nativeAliasSuffix"),const_cast<char*>("()Ljava/lang/String;"),
        reinterpret_cast<void*>(nativeAliasSuffix)},
        {const_cast<char*>("nativeCacheSession"),const_cast<char*>("(Ljava/lang/String;JZ)V"),
        reinterpret_cast<void*>(nativeCacheSession)},
        {const_cast<char*>("nativeGetSession"),const_cast<char*>("()Ljava/lang/String;"),
        reinterpret_cast<void*>(nativeGetSession)},
        {const_cast<char*>("nativeRequiresActionIntegrity"),const_cast<char*>("()Z"),
        reinterpret_cast<void*>(nativeRequiresActionIntegrity)},
        {const_cast<char*>("nativeClearSession"),const_cast<char*>("()V"),
        reinterpret_cast<void*>(nativeClearSession)},
        {const_cast<char*>("nativeInvalidateSession"),const_cast<char*>("(Ljava/lang/String;)V"),
        reinterpret_cast<void*>(nativeInvalidateSession)}};
    const jint registered=env->RegisterNatives(bridge,methods,16);
    env->DeleteLocalRef(bridge);
    return registered==JNI_OK?JNI_VERSION_1_6:JNI_ERR;
}
