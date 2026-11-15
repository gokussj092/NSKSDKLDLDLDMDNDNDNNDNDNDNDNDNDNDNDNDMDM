#include "admin_routes.h"
#include <jni.h>
#include <string>
namespace {
std::string bytes(JNIEnv* env,jbyteArray input){
    const auto n=env->GetArrayLength(input);std::string out(static_cast<std::size_t>(n),'\0');
    if(n) { env->GetByteArrayRegion(input,0,n,reinterpret_cast<jbyte*>(out.data())); }
    return out;
}
}
extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_ghostdeveloper_spdecode_admin_NativeAdminRoutes_planNative(JNIEnv* env,jobject,jbyteArray op,jbyteArray query,jint page,jint body_size){
    if(!op||!query||body_size<0||env->GetArrayLength(op)>40||env->GetArrayLength(query)>320)return nullptr;
    auto operation=bytes(env,op);auto q=bytes(env,query);if(env->ExceptionCheck())return nullptr;
    auto result=spdecode::admin::plan(operation,q,page,static_cast<std::size_t>(body_size));if(!result)return nullptr;
    auto c=env->FindClass("java/lang/String");if(!c)return nullptr;
    auto arr=env->NewObjectArray(3,c,nullptr);if(!arr)return nullptr;
    auto max=std::to_string(result->max_response);
    const char* values[]{result->path.c_str(),result->method,max.c_str()};
    for(int i=0;i<3;++i){auto v=env->NewStringUTF(values[i]);if(!v)return nullptr;env->SetObjectArrayElement(arr,i,v);env->DeleteLocalRef(v);if(env->ExceptionCheck())return nullptr;}
    return arr;
}
// Connection data exposed to Kotlin. Kotlin never hardcodes the origin,
// the cookie path or the session cookie names; it reads them here.
extern "C" JNIEXPORT jstring JNICALL
Java_com_ghostdeveloper_spdecode_admin_NativeAdminRoutes_originNative(JNIEnv* env,jobject){
    return env->NewStringUTF(spdecode::admin::kAdminOrigin);
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_ghostdeveloper_spdecode_admin_NativeAdminRoutes_cookiePathNative(JNIEnv* env,jobject){
    return env->NewStringUTF(spdecode::admin::kAdminCookiePath);
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_ghostdeveloper_spdecode_admin_NativeAdminRoutes_sessionCookieNameNative(JNIEnv* env,jobject,jboolean staff){
    return env->NewStringUTF(staff?spdecode::admin::kStaffSessionCookie:spdecode::admin::kAdminSessionCookie);
}
