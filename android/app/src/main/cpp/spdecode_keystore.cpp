#include "spdecode_keystore.h"
#include "spdecode_keystore_policy.h"
#include "spdecode_security.h"
#include <mbedtls/base64.h>
#include <mbedtls/platform_util.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

namespace spdecode {
namespace {
constexpr const char* kLegacy="spdecode.transport.v2";
constexpr const char* kPrefix="spdecode.transport.v3.";
std::mutex keystoreMutex;
std::string activeAlias;

std::string fromJava(JNIEnv* env,jstring value) {
    if(!value)return {};
    const char* chars=env->GetStringUTFChars(value,nullptr);
    if(!chars)throw std::runtime_error("CLOUD_KEY_UNAVAILABLE");
    std::string s(chars);
    env->ReleaseStringUTFChars(value,chars);
    return s;
}
struct Platform {
    JNIEnv* env;
    jclass cls;
    explicit Platform(JNIEnv* e):env(e),cls(env->FindClass(
            "com/ghostdeveloper/spdecode/cloud/CloudKeystorePlatform")) {
        if(!cls||env->ExceptionCheck())
            throw std::runtime_error("CLOUD_KEYSTORE_UNAVAILABLE");
    }
    ~Platform(){if(cls)env->DeleteLocalRef(cls);}
    jmethodID method(const char* name,const char* signature) const {
        auto m=env->GetStaticMethodID(cls,name,signature);
        if(!m||env->ExceptionCheck())
            throw std::runtime_error("CLOUD_KEYSTORE_UNAVAILABLE");
        return m;
    }
    jstring key(const std::string& alias) const {
        auto value=env->NewStringUTF(alias.c_str());
        if(!value||env->ExceptionCheck())
            throw std::runtime_error("CLOUD_KEYSTORE_UNAVAILABLE");
        return value;
    }
    std::vector<std::string> aliases() const {
        const auto m=method("aliases","()[Ljava/lang/String;");
        auto a=static_cast<jobjectArray>(env->CallStaticObjectMethod(cls,m));
        if(!a||env->ExceptionCheck())
            throw std::runtime_error("CLOUD_KEYSTORE_UNAVAILABLE");
        std::vector<std::string> result;
        const auto length=env->GetArrayLength(a);
        if(length<0||length>2048)throw std::runtime_error("CLOUD_KEYSTORE_UNAVAILABLE");
        result.reserve(static_cast<size_t>(length));
        for(jsize i=0;i<length;++i){
            auto item=static_cast<jstring>(env->GetObjectArrayElement(a,i));
            if(env->ExceptionCheck())throw std::runtime_error("CLOUD_KEYSTORE_UNAVAILABLE");
            result.push_back(fromJava(env,item));
            env->DeleteLocalRef(item);
        }
        env->DeleteLocalRef(a);
        return managedKeystoreAliases(result);
    }
    bool contains(const std::string& alias) const {
        auto a=key(alias);
        const auto m=method("contains","(Ljava/lang/String;)Z");
        bool yes=env->CallStaticBooleanMethod(cls,m,a)==JNI_TRUE;
        env->DeleteLocalRef(a);
        if(env->ExceptionCheck())throw std::runtime_error("CLOUD_KEYSTORE_UNAVAILABLE");
        return yes;
    }
    std::string publicKey(const std::string& alias) const {
        auto a=key(alias);
        const auto m=method("publicKey","(Ljava/lang/String;)Ljava/lang/String;");
        auto value=static_cast<jstring>(env->CallStaticObjectMethod(cls,m,a));
        env->DeleteLocalRef(a);
        if(!value||env->ExceptionCheck())throw std::runtime_error("CLOUD_KEY_UNAVAILABLE");
        auto encoded=fromJava(env,value);
        env->DeleteLocalRef(value);
        return encoded;
    }
    jobject privateKey(const std::string& alias) const {
        auto a=key(alias);
        const auto m=method("privateKey","(Ljava/lang/String;)Ljava/security/PrivateKey;");
        jobject result=env->CallStaticObjectMethod(cls,m,a);
        env->DeleteLocalRef(a);
        if(!result||env->ExceptionCheck())throw std::runtime_error("CLOUD_KEY_UNAVAILABLE");
        return result;
    }
    jobjectArray chain(const std::string& alias) const {
        auto a=key(alias);
        const auto m=method("chain","(Ljava/lang/String;)[Ljava/lang/String;");
        auto result=static_cast<jobjectArray>(env->CallStaticObjectMethod(cls,m,a));
        env->DeleteLocalRef(a);
        if(!result||env->ExceptionCheck())
            throw std::runtime_error("CLOUD_ATTESTATION_UNAVAILABLE");
        return result;
    }
    void erase(const std::string& alias) const {
        auto a=key(alias);
        const auto m=method("delete","(Ljava/lang/String;)V");
        env->CallStaticVoidMethod(cls,m,a);
        env->DeleteLocalRef(a);
        if(env->ExceptionCheck())throw std::runtime_error("CLOUD_KEYSTORE_UNAVAILABLE");
    }
    void generate(const std::string& alias,jbyteArray challenge,bool strong) const {
        auto a=key(alias);
        const auto m=method("generate","(Ljava/lang/String;[BZ)V");
        env->CallStaticVoidMethod(cls,m,a,challenge,strong?JNI_TRUE:JNI_FALSE);
        env->DeleteLocalRef(a);
        // Keep the original platform exception visible for StrongBox classification.
    }
};
void ioError(JNIEnv* env,const char* message){
    if(env->ExceptionCheck())return;
    auto cls=env->FindClass("java/io/IOException");
    if(cls)env->ThrowNew(cls,message);
}
std::string active(Platform& p){
    const auto aliases=p.aliases();
    if(!activeAlias.empty() && std::find(aliases.begin(),aliases.end(),activeAlias)!=aliases.end())
        return activeAlias;
    activeAlias=preferredKeystoreAlias(aliases);
    if(activeAlias.empty()){
        if(!p.contains(kLegacy))p.generate(kLegacy,nullptr,false);
        if(p.env->ExceptionCheck())throw std::runtime_error("CLOUD_KEYSTORE_UNAVAILABLE");
        activeAlias=kLegacy;
    }
    return activeAlias;
}
std::string requestedKey(JNIEnv* env,const std::string& bearer){
    // Bearer format is a signed, server-issued base64url JSON segment.
    // Invalid/legacy non-JSON tokens preserve the original active-alias fallback.
    if(bearer.empty()||bearer.size()>2048)return {};
    const auto dot=bearer.find('.');
    if(dot==std::string::npos||dot==0)return {};
    std::string segment=bearer.substr(0,dot);
    for(char& c:segment){
        if(c=='-')c='+';
        else if(c=='_')c='/';
        else if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||
                  (c>='0'&&c<='9')))return {};
    }
    if(segment.size()%4==1)return {};
    segment.append((4-segment.size()%4)%4,'=');
    std::vector<unsigned char> decoded(segment.size());
    size_t length=0;
    if(mbedtls_base64_decode(decoded.data(),decoded.size(),&length,
                             reinterpret_cast<const unsigned char*>(segment.data()),
                             segment.size())!=0)return {};
    if(length==0 || length>2048)return {};
    jbyteArray data=env->NewByteArray(static_cast<jsize>(length));
    if(!data)return {};
    env->SetByteArrayRegion(data,0,static_cast<jsize>(length),
                            reinterpret_cast<const jbyte*>(decoded.data()));
    mbedtls_platform_zeroize(decoded.data(),decoded.size());
    auto stringClass=env->FindClass("java/lang/String");
    auto constructor=stringClass?env->GetMethodID(stringClass,"<init>",
        "([BLjava/lang/String;)V"):nullptr;
    auto encoding=env->NewStringUTF("UTF-8");
    jobject jsonText=constructor?env->NewObject(stringClass,constructor,data,encoding):nullptr;
    env->DeleteLocalRef(data);
    if(encoding)env->DeleteLocalRef(encoding);
    auto jsonClass=env->FindClass("org/json/JSONObject");
    auto jsonConstructor=jsonClass?env->GetMethodID(jsonClass,"<init>","(Ljava/lang/String;)V"):nullptr;
    auto document=jsonConstructor&&jsonText?
        env->NewObject(jsonClass,jsonConstructor,jsonText):nullptr;
    if(jsonText)env->DeleteLocalRef(jsonText);
    auto optString=jsonClass?env->GetMethodID(jsonClass,"optString",
        "(Ljava/lang/String;)Ljava/lang/String;"):nullptr;
    auto field=env->NewStringUTF("key");
    auto value=optString&&document&&field?
        static_cast<jstring>(env->CallObjectMethod(document,optString,field)):nullptr;
    if(field)env->DeleteLocalRef(field);
    if(document)env->DeleteLocalRef(document);
    std::string requested;
    if(!env->ExceptionCheck() && value)requested=fromJava(env,value);
    if(value)env->DeleteLocalRef(value);
    if(env->ExceptionCheck())env->ExceptionClear(); // malformed claim -> no key hint
    return validKeyClaim(requested)?requested:std::string();
}
std::string aliasFor(Platform& p,const std::string& bearer){
    const std::string wanted=requestedKey(p.env,bearer);
    if(wanted.empty())return active(p);
    for(const auto& alias:p.aliases()){
        if(p.publicKey(alias)==wanted)return alias;
    }
    throw std::runtime_error("CLOUD_KEY_UNAVAILABLE");
}
bool isStrongboxUnavailable(JNIEnv* env,jthrowable failure){
    auto cls=env->FindClass("android/security/keystore/StrongBoxUnavailableException");
    if(!cls||env->ExceptionCheck()){env->ExceptionClear();return false;}
    return env->IsInstanceOf(failure,cls)==JNI_TRUE;
}
void ignoreCleanup(Platform& p,const std::string& alias){
    try{p.erase(alias);}
    catch(const std::exception&){if(p.env->ExceptionCheck())p.env->ExceptionClear();}
}
std::int64_t currentMillis(){
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}
std::vector<unsigned char> decodeChallenge(const std::string& raw){
    std::string text=raw;
    for(char& c:text)if(c=='-')c='+';else if(c=='_')c='/';
    text+='=';
    std::vector<unsigned char> result(40);
    size_t size=0;
    if(mbedtls_base64_decode(result.data(),result.size(),&size,
        reinterpret_cast<const unsigned char*>(text.data()),text.size())!=0||size!=32)
        throw std::runtime_error("CLOUD_ATTESTATION_UNAVAILABLE");
    result.resize(size);
    return result;
}
} // namespace

jstring currentHardwarePublicKey(JNIEnv* env){
    try{
        std::lock_guard<std::mutex> guard(keystoreMutex);
        Platform p(env);
        const auto name=active(p);
        const auto key=p.publicKey(name);
        if(!validKeyClaim(key))throw std::runtime_error("CLOUD_KEY_UNAVAILABLE");
        return env->NewStringUTF(key.c_str());
    }catch(const std::exception& error){
        ioError(env,error.what());return nullptr;
    }
}
jobject privateSigningKeyForBearer(JNIEnv* env,jstring bearer){
    try{
        std::lock_guard<std::mutex> guard(keystoreMutex);
        Platform p(env);
        return p.privateKey(aliasFor(p,fromJava(env,bearer)));
    }catch(const std::exception& error){
        ioError(env,error.what());return nullptr;
    }
}
jobjectArray createHardwareAttestation(JNIEnv* env,jstring challengeArg,jstring levelArg){
    try{
        std::lock_guard<std::mutex> guard(keystoreMutex);
        const std::string challenge=fromJava(env,challengeArg);
        const std::string level=fromJava(env,levelArg);
        if(!validEnrollmentChallenge(challenge,level))
            throw std::runtime_error("CLOUD_ATTESTATION_UNAVAILABLE");
        Platform p(env);
        (void)active(p);
        const auto now=currentMillis();
        for(const auto& alias:p.aliases()){
            if(shouldPurgeKeystoreAlias(alias,activeAlias,now))p.erase(alias);
        }
        if(p.aliases().size()>=8)
            throw std::runtime_error("CLOUD_KEY_ENROLLMENT_LIMIT");
        const std::string alias=std::string(kPrefix)+std::to_string(now)+"."+
                                makeAliasSuffix();
        auto challengeBytes=decodeChallenge(challenge);
        auto challengeArray=env->NewByteArray(static_cast<jsize>(challengeBytes.size()));
        if(!challengeArray)throw std::runtime_error("CLOUD_ATTESTATION_UNAVAILABLE");
        env->SetByteArrayRegion(challengeArray,0,
            static_cast<jsize>(challengeBytes.size()),
            reinterpret_cast<const jbyte*>(challengeBytes.data()));
        mbedtls_platform_zeroize(challengeBytes.data(),challengeBytes.size());
        if(env->ExceptionCheck())throw std::runtime_error("CLOUD_ATTESTATION_UNAVAILABLE");
        auto version=env->FindClass("android/os/Build$VERSION");
        auto sdkField=version?env->GetStaticFieldID(version,"SDK_INT","I"):nullptr;
        if(!sdkField||env->ExceptionCheck())
            throw std::runtime_error("CLOUD_ATTESTATION_UNAVAILABLE");
        const auto sdk=env->GetStaticIntField(version,sdkField);
        if(level=="strongbox"&&sdk<28){
            env->DeleteLocalRef(challengeArray);
            throw std::runtime_error("CLOUD_STRONGBOX_UNAVAILABLE");
        }
        p.generate(alias,challengeArray,sdk>=28);
        if(env->ExceptionCheck()){
            auto error=env->ExceptionOccurred();
            env->ExceptionClear();
            const bool unavailable=sdk>=28&&isStrongboxUnavailable(env,error);
            env->DeleteLocalRef(error);
            if(!unavailable){
                ignoreCleanup(p,alias);
                env->DeleteLocalRef(challengeArray);
                throw std::runtime_error("CLOUD_ATTESTATION_UNAVAILABLE");
            }
            if(level=="strongbox"){
                ignoreCleanup(p,alias);
                env->DeleteLocalRef(challengeArray);
                throw std::runtime_error("CLOUD_STRONGBOX_UNAVAILABLE");
            }
            ignoreCleanup(p,alias);
            p.generate(alias,challengeArray,false);
        }
        env->DeleteLocalRef(challengeArray);
        if(env->ExceptionCheck()){
            env->ExceptionClear();
            ignoreCleanup(p,alias);
            throw std::runtime_error("CLOUD_ATTESTATION_UNAVAILABLE");
        }
        jobjectArray chain=nullptr;
        try{
            chain=p.chain(alias);
            const auto count=env->GetArrayLength(chain);
            if(count<2||count>8)
                throw std::runtime_error("CLOUD_ATTESTATION_UNAVAILABLE");
            for(jsize i=0;i<count;++i){
                auto item=static_cast<jstring>(env->GetObjectArrayElement(chain,i));
                const auto data=fromJava(env,item);
                if(item)env->DeleteLocalRef(item);
                if(data.empty()||data.size()>32768)
                    throw std::runtime_error("CLOUD_ATTESTATION_UNAVAILABLE");
            }
        }catch(const std::exception&){
            if(env->ExceptionCheck())env->ExceptionClear();
            ignoreCleanup(p,alias);
            throw;
        }
        activeAlias=alias;
        return chain;
    }catch(const std::exception& error){
        ioError(env,error.what());return nullptr;
    }
}
} // namespace spdecode
