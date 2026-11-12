#include <jni.h>
#include <cstddef>
#include <cstdint>
#include <string_view>

// Client-side UX validation. The server remains the security authority.
namespace {
bool valid_username(std::string_view s) {
    if(s.size()<3 || s.size()>24 || s[0]<'a' || s[0]>'z')return false;
    for(char c:s)if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'))return false;
    constexpr std::string_view blocked[]={"admin","administrator","support","soporte",
        "spdecode","root","system","api","null","undefined","deleted","security",
        "billing","moderator"};
    for(auto forbidden:blocked)if(s==forbidden)return false;
    return true;
}
bool valid_display_name(JNIEnv* env,jstring value) {
    if(!value)return false;
    const jsize size=env->GetStringLength(value);
    if(size<1 || size>160)return false;
    const jchar* chars=env->GetStringChars(value,nullptr);
    if(!chars)return false;
    size_t codepoints=0;
    bool valid=true;
    for(jsize i=0;i<size;i++){
        uint32_t cp=chars[i];
        if(cp>=0xD800&&cp<=0xDBFF){
            if(i+1>=size || chars[i+1]<0xDC00 || chars[i+1]>0xDFFF){valid=false;break;}
            cp=0x10000+((cp-0xD800)<<10)+(chars[++i]-0xDC00);
        }else if(cp>=0xDC00&&cp<=0xDFFF){valid=false;break;}
        if(cp<0x20 || (cp>=0x7F&&cp<=0x9F) ||
           (cp>=0x202A&&cp<=0x202E) || (cp>=0x2066&&cp<=0x2069)){
            valid=false;break;
        }
        if(++codepoints>80){valid=false;break;}
    }
    env->ReleaseStringChars(value,chars);
    return valid && codepoints>=1;
}
}
extern "C" JNIEXPORT jboolean JNICALL
Java_com_ghostdeveloper_spdecode_NativeProfileRules_validUsername(
    JNIEnv* env,jobject,jstring value){
    if(!value)return JNI_FALSE;
    const char* raw=env->GetStringUTFChars(value,nullptr);
    if(!raw)return JNI_FALSE;
    const bool ok=valid_username(raw);
    env->ReleaseStringUTFChars(value,raw);
    return ok?JNI_TRUE:JNI_FALSE;
}
extern "C" JNIEXPORT jboolean JNICALL
Java_com_ghostdeveloper_spdecode_NativeProfileRules_validDisplayName(
    JNIEnv* env,jobject,jstring value){
    return valid_display_name(env,value)?JNI_TRUE:JNI_FALSE;
}
