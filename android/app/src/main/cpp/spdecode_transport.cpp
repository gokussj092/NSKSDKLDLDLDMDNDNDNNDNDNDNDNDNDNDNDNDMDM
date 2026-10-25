#include <jni.h>
#include <algorithm>
#include <cctype>
#include <string>

#include "cloud_origin.h"

namespace {
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
bool safePath(const std::string& path) {
    return path == "/api/v1/session/challenge" ||
        path == "/api/v1/session/qa" ||
        path == "/api/v1/session" ||
        path == "/api/v1/npvs/identity" ||
        path == "/api/v1/decode/file" ||
        path == "/api/v1/decode/text" ||
        path == "/api/v1/decode/import/cloud" ||
        path == "/api/v1/decode/import/catalog/remote" ||
        path == "/api/v1/server-vpn/catalog" ||
        path == "/api/v1/server-vpn/watch" ||
        path == "/api/v1/whats-new" ||
        path == "/api/v1/server-vpn/icon" ||
        path == "/api/v1/server-vpn/decode" ||
        path == "/api/v1/telemetry";
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
jstring post(JNIEnv* env,jstring pathArg,jstring bodyArg,jstring bearerArg,jstring versionArg) {
    const std::string base=SPDECODE_CLOUD_ORIGIN;
    const std::string path=utf(env,pathArg);
    const std::string body=utf(env,bodyArg);
    const std::string bearer=utf(env,bearerArg);
    const std::string clientVersion=utf(env,versionArg);
    const bool validVersion=clientVersion.size()>=5 && clientVersion.size()<=11 &&
        std::all_of(clientVersion.begin(),clientVersion.end(),[](unsigned char c){
            return std::isdigit(c) || c=='.';
        }) && std::count(clientVersion.begin(),clientVersion.end(),'.')==2;
    if (!validVersion || !safeBase(base) || !safePath(path) || !safeBearer(bearer) ||
        body.empty() || body.size()>kMaxRequestBytes) {
        fail(env,"CLOUD_NATIVE_REQUEST_REJECTED");return nullptr;
    }
    jclass urlClass = env->FindClass("java/net/URL");
    jclass connectionClass=env->FindClass("java/net/URLConnection");
    jclass httpClass=env->FindClass("java/net/HttpURLConnection");
    jclass httpsClass=env->FindClass("javax/net/ssl/HttpsURLConnection");
    jclass streamClass=env->FindClass("java/io/InputStream");
    jclass outputClass=env->FindClass("java/io/OutputStream");
    jclass stringClass=env->FindClass("java/lang/String");
    if (!urlClass || !connectionClass || !httpClass || !httpsClass ||
        !streamClass || !outputClass || !stringClass) {
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
    const jmethodID bytesMethod=env->GetMethodID(stringClass,"getBytes","(Ljava/lang/String;)[B");
    if (!urlCtor || !open || !setMethod || !setRedirect || !setConnect ||
        !setRead || !setOutput || !setProperty || !setLength ||
        !getOutput || !getInput || !getError || !statusMethod || !disconnect ||
        !write || !closeOutput || !read || !closeInput || !bytesMethod) {
        fail(env,"CLOUD_NATIVE_METHOD_UNAVAILABLE");return nullptr;
    }

    jstring urlString=env->NewStringUTF((base+path).c_str());
    jobject url=env->NewObject(urlClass,urlCtor,urlString);
    env->DeleteLocalRef(urlString);
    if (!url || clearException(env)) {
        fail(env,"CLOUD_NATIVE_URL_REJECTED");return nullptr;
    }
    jobject conn=env->CallObjectMethod(url,open);
    env->DeleteLocalRef(url);
    if (!conn || clearException(env)) {
        fail(env,"CLOUD_NATIVE_CONNECT_FAILED");return nullptr;
    }
    if (!env->IsInstanceOf(conn,httpsClass)) {
        env->DeleteLocalRef(conn);
        fail(env,"CLOUD_NATIVE_TLS_REQUIRED");return nullptr;
    }
    jstring method=jstr(env,"POST");
    env->CallVoidMethod(conn,setMethod,method);
    env->DeleteLocalRef(method);
    env->CallVoidMethod(conn,setRedirect,JNI_FALSE);
    env->CallVoidMethod(conn,setConnect,kConnectTimeoutMs);
    // Do not relax ordinary decoder/session timeouts. NUR server catalog
    // can require up to 120s on the remote worker for nested Argon2id fields.
    const jint readTimeout = (path == "/api/v1/decode/import/catalog/remote" ||
        path == "/api/v1/server-vpn/decode")
        ? kNurCatalogReadTimeoutMs : kReadTimeoutMs;
    env->CallVoidMethod(conn,setRead,readTimeout);
    env->CallVoidMethod(conn,setOutput,JNI_TRUE);
    env->CallVoidMethod(conn,setLength,8192);
    bool ok=!env->ExceptionCheck();
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"Content-Type","application/json");
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"Accept","application/json");
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"Accept-Encoding","identity");
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"Cache-Control","no-store");
    if(ok)ok=setHeader(env,conn,connectionClass,setProperty,"X-SPDecode-App-Version",clientVersion);
    // Capability negotiation for the new credential dialog. Older APKs omit
    // this header automatically. It is not trusted for authentication.
    if(ok && (path == "/api/v1/decode/file" || path == "/api/v1/decode/text"))
        ok=setHeader(env,conn,connectionClass,setProperty,"X-SPDecode-Credential-Prompts","1");
    if(ok && path == "/api/v1/server-vpn/catalog")
        ok=setHeader(env,conn,connectionClass,setProperty,"X-SPDecode-NPV-Identities","1");
    if(ok && !bearer.empty())ok=setHeader(env,conn,connectionClass,setProperty,"Authorization","Bearer "+bearer);
    if(!ok) {
        clearException(env);env->CallVoidMethod(conn,disconnect);
        env->DeleteLocalRef(conn);
        fail(env,"CLOUD_NATIVE_HEADERS_FAILED");return nullptr;
    }
    jobject os=env->CallObjectMethod(conn,getOutput);
    if(!os || clearException(env)) {
        env->CallVoidMethod(conn,disconnect);env->DeleteLocalRef(conn);
        fail(env,"CLOUD_NATIVE_NETWORK_UNAVAILABLE");return nullptr;
    }
    jstring bodyString=env->NewStringUTF(body.c_str());
    jstring utf8=env->NewStringUTF("UTF-8");
    jbyteArray bodyBytes=static_cast<jbyteArray>(env->CallObjectMethod(bodyString,bytesMethod,utf8));
    env->DeleteLocalRef(bodyString);env->DeleteLocalRef(utf8);
    if(bodyBytes && !env->ExceptionCheck())env->CallVoidMethod(os,write,bodyBytes);
    if(bodyBytes)env->DeleteLocalRef(bodyBytes);
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
    const size_t replyCap=(path=="/api/v1/server-vpn/decode" &&
        body.find("mkk-hyper")!=std::string::npos)
        ? kMaxMkkReplyBytes : kMaxReplyBytes;
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
    const jmethodID stringUtf8Ctor=env->GetMethodID(stringClass,"<init>",
                                                   "([BLjava/lang/String;)V");
    jstring encoding=jstr(env,"UTF-8");
    jstring decoded=static_cast<jstring>(env->NewObject(stringClass,stringUtf8Ctor,raw,encoding));
    env->DeleteLocalRef(raw);
    env->DeleteLocalRef(encoding);
    if(decoded==nullptr || clearException(env)){
        fail(env,"CLOUD_NATIVE_RESPONSE_ENCODING");return nullptr;
    }
    return decoded;
}
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_ghostdeveloper_spdecode_cloud_CloudNativeTransport_postNative(
    JNIEnv* env,jobject,jstring endpoint,jstring body,jstring bearer,jstring clientVersion) {
    return post(env,endpoint,body,bearer,clientVersion);
}
