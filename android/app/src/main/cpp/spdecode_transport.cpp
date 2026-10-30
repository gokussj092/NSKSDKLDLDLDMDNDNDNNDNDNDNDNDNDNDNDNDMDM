#include <jni.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "spdecode_hpke.h"
#include <mbedtls/platform_util.h>
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
        reinterpret_cast<void*>(discardHpke)}};
    const jint registered=env->RegisterNatives(bridge,methods,4);
    env->DeleteLocalRef(bridge);
    return registered==JNI_OK?JNI_VERSION_1_6:JNI_ERR;
}
