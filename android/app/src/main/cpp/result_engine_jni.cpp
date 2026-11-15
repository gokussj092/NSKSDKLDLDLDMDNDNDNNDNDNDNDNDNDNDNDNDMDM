#include "result_engine.h"
#include <jni.h>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <stdexcept>
#include <algorithm>

namespace {
using spdecode_result::Document;
std::mutex mutex;
std::unordered_map<jlong,std::shared_ptr<Document>> documents;
jlong nextHandle=1;
void failure(JNIEnv* env){if(!env->ExceptionCheck()){const auto cls=env->FindClass("java/io/IOException");if(cls)env->ThrowNew(cls,"RESULT_PREVIEW_UNAVAILABLE");}}
std::shared_ptr<Document> get(jlong id){std::lock_guard<std::mutex> lock(mutex);auto it=documents.find(id);if(it==documents.end())throw std::runtime_error("closed");return it->second;}
jbyteArray bytes(JNIEnv* env,const std::string& value){
    if(value.size()>65536)throw std::runtime_error("bound");
    const auto out=env->NewByteArray(static_cast<jsize>(value.size()));
    if(out&&!value.empty())env->SetByteArrayRegion(out,0,static_cast<jsize>(value.size()),reinterpret_cast<const jbyte*>(value.data()));
    return out;
}
jlong openResult(JNIEnv* env,jclass,jstring data){
    try{
        if(!data)throw std::runtime_error("input");
        const auto size=env->GetStringLength(data);
        if(size<1||static_cast<size_t>(size)>Document::MaxBytes)throw std::runtime_error("size");
        std::lock_guard<std::mutex> lock(mutex);size_t used=0;for(const auto& p:documents)used+=p.second->bytes();
        if(documents.size()>=2||used+static_cast<size_t>(size)>Document::MaxBytes)throw std::runtime_error("budget");
        std::string raw;raw.reserve(static_cast<size_t>(size));uint32_t high=0;
        for(jsize offset=0;offset<size;offset+=4096){
            jchar buffer[4096];const jsize count=std::min<jsize>(4096,size-offset);env->GetStringRegion(data,offset,count,buffer);
            if(env->ExceptionCheck())return 0;
            for(jsize i=0;i<count;++i){uint32_t cp=buffer[i];
                if(high){if(cp<0xdc00||cp>0xdfff)throw std::runtime_error("utf16");cp=0x10000+((high-0xd800)<<10)+cp-0xdc00;high=0;}
                else if(cp>=0xd800&&cp<=0xdbff){high=cp;continue;}else if(cp>=0xdc00&&cp<=0xdfff)throw std::runtime_error("utf16");
                if(cp<128)raw+=static_cast<char>(cp);
                else if(cp<2048){raw+=static_cast<char>(0xc0|(cp>>6));raw+=static_cast<char>(0x80|(cp&63));}
                else if(cp<65536){raw+=static_cast<char>(0xe0|(cp>>12));raw+=static_cast<char>(0x80|((cp>>6)&63));raw+=static_cast<char>(0x80|(cp&63));}
                else{raw+=static_cast<char>(0xf0|(cp>>18));raw+=static_cast<char>(0x80|((cp>>12)&63));raw+=static_cast<char>(0x80|((cp>>6)&63));raw+=static_cast<char>(0x80|(cp&63));}
                if(raw.size()>Document::MaxBytes)throw std::runtime_error("budget");
            }
        }
        if(high)throw std::runtime_error("utf16");
        if(used+raw.size()>Document::MaxBytes)throw std::runtime_error("budget");
        if(env->ExceptionCheck())return 0;
        auto doc=std::make_shared<Document>(std::move(raw));const jlong id=nextHandle++;documents.emplace(id,std::move(doc));return id;
    }catch(...){failure(env);return 0;}
}
jbyteArray page(JNIEnv* env,jclass,jlong id,jint parent,jint offset,jint limit,jboolean mask){try{return bytes(env,get(id)->page(parent,offset,limit,mask==JNI_TRUE));}catch(...){failure(env);return nullptr;}}
jbyteArray value(JNIEnv* env,jclass,jlong id,jint node,jint offset,jint limit,jboolean mask){try{return bytes(env,get(id)->value(node,offset,limit,mask==JNI_TRUE));}catch(...){failure(env);return nullptr;}}
jbyteArray original(JNIEnv* env,jclass,jlong id,jint offset,jint limit){try{if(offset<0||limit<1)throw std::runtime_error("range");return bytes(env,get(id)->original(static_cast<size_t>(offset),static_cast<size_t>(limit)));}catch(...){failure(env);return nullptr;}}
jint lineCount(JNIEnv* env,jclass,jlong id){try{return static_cast<jint>(get(id)->lines());}catch(...){failure(env);return 0;}}
jint columnCount(JNIEnv* env,jclass,jlong id){try{return static_cast<jint>(get(id)->columns());}catch(...){failure(env);return 0;}}
jint findNext(JNIEnv* env,jclass,jlong id,jbyteArray term,jint start,jboolean mask){
    try{
        if(!term||env->GetArrayLength(term)<1||env->GetArrayLength(term)>256)return -1;
        std::string needle(static_cast<size_t>(env->GetArrayLength(term)),'\0');
        env->GetByteArrayRegion(term,0,static_cast<jsize>(needle.size()),
            reinterpret_cast<jbyte*>(&needle[0]));
        if(env->ExceptionCheck())return -1;
        return static_cast<jint>(get(id)->findNext(needle,start,mask==JNI_TRUE));
    }catch(...){failure(env);return -1;}
}
jbyteArray lineWindow(JNIEnv* env,jclass,jlong id,jint line,jint column,jint count,jboolean mask){try{return bytes(env,get(id)->lineWindow(line,column,count,mask==JNI_TRUE));}catch(...){failure(env);return nullptr;}}
void closeResult(JNIEnv*,jclass,jlong id){std::lock_guard<std::mutex> lock(mutex);documents.erase(id);}
jint length(JNIEnv* env,jclass,jlong id){try{return static_cast<jint>(get(id)->bytes());}catch(...){failure(env);return 0;}}
}
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm,void*){
    JNIEnv* env=nullptr;if(vm->GetEnv(reinterpret_cast<void**>(&env),JNI_VERSION_1_6)!=JNI_OK)return JNI_ERR;
    auto cls=env->FindClass("com/ghostdeveloper/spdecode/results/NativeResultEngine");if(!cls)return JNI_ERR;
    const JNINativeMethod methods[]={
        {const_cast<char*>("nativeLineCount"),const_cast<char*>("(J)I"),reinterpret_cast<void*>(lineCount)},
        {const_cast<char*>("nativeColumnCount"),const_cast<char*>("(J)I"),reinterpret_cast<void*>(columnCount)},
        {const_cast<char*>("nativeLineWindow"),const_cast<char*>("(JIIIZ)[B"),reinterpret_cast<void*>(lineWindow)},
        {const_cast<char*>("nativeFindNext"),const_cast<char*>("(J[BIZ)I"),reinterpret_cast<void*>(findNext)},
        {const_cast<char*>("nativeOpen"),const_cast<char*>("(Ljava/lang/String;)J"),reinterpret_cast<void*>(openResult)},
        {const_cast<char*>("nativeLength"),const_cast<char*>("(J)I"),reinterpret_cast<void*>(length)},
        {const_cast<char*>("nativePage"),const_cast<char*>("(JIIIZ)[B"),reinterpret_cast<void*>(page)},
        {const_cast<char*>("nativeValue"),const_cast<char*>("(JIIIZ)[B"),reinterpret_cast<void*>(value)},
        {const_cast<char*>("nativeOriginal"),const_cast<char*>("(JII)[B"),reinterpret_cast<void*>(original)},
        {const_cast<char*>("nativeClose"),const_cast<char*>("(J)V"),reinterpret_cast<void*>(closeResult)}};
    const int status=env->RegisterNatives(cls,methods,sizeof(methods)/sizeof(methods[0]));env->DeleteLocalRef(cls);return status==0?JNI_VERSION_1_6:JNI_ERR;
}

