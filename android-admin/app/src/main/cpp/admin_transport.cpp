#include "admin_routes.h"
#include <jni.h>
#include <chrono>
#include <string>
#include <vector>

namespace {
constexpr const char* origin="https://panel.spdecode.xyz";
std::string bytes(JNIEnv* e,jbyteArray a){
 if(!a)return {};
 auto n=e->GetArrayLength(a);std::string s(static_cast<size_t>(n),'\0');
 if(n)e->GetByteArrayRegion(a,0,n,reinterpret_cast<jbyte*>(s.data()));
 return s;
}
bool cookie_ok(const std::string& s){
 if(s.empty())return true;
 if(s.size()>2048)return false;
 const auto pos=s.find('=');
 if(pos==std::string::npos)return false;
 const auto name=s.substr(0,pos);
 if(name!="spdecode_admin_session"&&name!="spdecode_staff_session")return false;
 if(pos+1==s.size())return false;
 for(size_t i=pos+1;i<s.size();++i){const auto c=s[i];
  if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'))return false;
 }return true;
}
struct Connection {
 JNIEnv* e;jobject value=nullptr;jclass cls=nullptr;jobject stream=nullptr;
 explicit Connection(JNIEnv* env):e(env){}
 ~Connection(){
  if(e->ExceptionCheck())e->ExceptionClear();
  if(stream){auto c=e->GetObjectClass(stream);auto m=e->GetMethodID(c,"close","()V");
   if(m)e->CallVoidMethod(stream,m);
   if(e->ExceptionCheck())e->ExceptionClear();
   e->DeleteLocalRef(c);}
  if(value&&cls){auto m=e->GetMethodID(cls,"disconnect","()V");if(m)e->CallVoidMethod(value,m);}
  if(e->ExceptionCheck())e->ExceptionClear();
 }
};
jobjectArray result(JNIEnv* e,int code,const std::string& body,const std::string& cookies){
 if(e->ExceptionCheck())e->ExceptionClear();
 auto c=e->FindClass("[B");auto a=e->NewObjectArray(3,c,nullptr);
 if(!a)return nullptr;
 const std::string values[]{std::to_string(code),body,cookies};
 for(int i=0;i<3;++i){auto b=e->NewByteArray(static_cast<jsize>(values[i].size()));if(!b)return nullptr;
  if(!values[i].empty())e->SetByteArrayRegion(b,0,static_cast<jsize>(values[i].size()),reinterpret_cast<const jbyte*>(values[i].data()));
  e->SetObjectArrayElement(a,i,b);e->DeleteLocalRef(b);}
 return a;
}
}
extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_ghostdeveloper_spdecode_admin_NativeAdminRoutes_exchangeNative(JNIEnv* e,jobject,jbyteArray operation,jbyteArray query,jint page,jbyteArray body,jbyteArray cookie){
 if(!operation||!query||!body||!cookie||e->GetArrayLength(operation)>40||e->GetArrayLength(query)>320||
  e->GetArrayLength(body)>16384||e->GetArrayLength(cookie)>2048)return result(e,0,"INVALID_REQUEST","");
 const auto op=bytes(e,operation),q=bytes(e,query),token=bytes(e,cookie);
 const auto plan=spdecode::admin::plan(op,q,page,static_cast<size_t>(e->GetArrayLength(body)));
 if(!plan||!cookie_ok(token))return result(e,0,"INVALID_REQUEST","");
 if(op!="login"&&token.empty())return result(e,401,"{\"error\":{\"code\":\"UNAUTHORIZED\"}}","");
 Connection connection(e);
 auto failure=[&](const char* error){return result(e,0,error,"");};
 auto urlClass=e->FindClass("java/net/URL");
 if(!urlClass)return failure("NETWORK_ERROR");
 auto ctor=e->GetMethodID(urlClass,"<init>","(Ljava/lang/String;)V");
 auto urlText=e->NewStringUTF((std::string(origin)+plan->path).c_str());
 auto url=e->NewObject(urlClass,ctor,urlText);
 if(e->ExceptionCheck()||!url)return failure("NETWORK_ERROR");
 auto open=e->GetMethodID(urlClass,"openConnection","()Ljava/net/URLConnection;");
 connection.value=e->CallObjectMethod(url,open);
 connection.cls=e->FindClass("javax/net/ssl/HttpsURLConnection");
 if(e->ExceptionCheck()||!connection.value||!connection.cls||!e->IsInstanceOf(connection.value,connection.cls))return failure("NETWORK_ERROR");
 auto cls=connection.cls;auto conn=connection.value;
 auto callInt=[&](const char* name,int n){auto m=e->GetMethodID(cls,name,"(I)V");e->CallVoidMethod(conn,m,n);};
 auto callBool=[&](const char* name,bool b){auto m=e->GetMethodID(cls,name,"(Z)V");e->CallVoidMethod(conn,m,static_cast<jboolean>(b));};
 auto header=[&](const char* key,const std::string& value){
  auto m=e->GetMethodID(cls,"setRequestProperty","(Ljava/lang/String;Ljava/lang/String;)V");
  auto k=e->NewStringUTF(key),v=e->NewStringUTF(value.c_str());e->CallVoidMethod(conn,m,k,v);e->DeleteLocalRef(k);e->DeleteLocalRef(v);
 };
 callInt("setConnectTimeout",10000);callInt("setReadTimeout",20000);callBool("setInstanceFollowRedirects",false);callBool("setUseCaches",false);
 auto method=e->NewStringUTF(plan->method);e->CallVoidMethod(conn,e->GetMethodID(cls,"setRequestMethod","(Ljava/lang/String;)V"),method);
 header("Accept","application/json");header("Cache-Control","no-store");
 if(op!="login")header("Cookie",token);
 if(std::string(plan->method)=="POST"){
  header("Origin",origin);header("X-SPDECODE-ADMIN-ACTION","1");header("Content-Type","application/json");
  callBool("setDoOutput",true);callInt("setFixedLengthStreamingMode",e->GetArrayLength(body));
  auto output=e->CallObjectMethod(conn,e->GetMethodID(cls,"getOutputStream","()Ljava/io/OutputStream;"));
  if(e->ExceptionCheck()||!output)return failure("NETWORK_ERROR");
  auto outClass=e->GetObjectClass(output);e->CallVoidMethod(output,e->GetMethodID(outClass,"write","([B)V"),body);
  if(e->ExceptionCheck())return failure("NETWORK_ERROR");
  e->CallVoidMethod(output,e->GetMethodID(outClass,"close","()V"));
 }
 if(e->ExceptionCheck())return failure("NETWORK_ERROR");
 const auto status=e->CallIntMethod(conn,e->GetMethodID(cls,"getResponseCode","()I"));
 if(e->ExceptionCheck())return failure("NETWORK_ERROR");
 if(status>=300&&status<400)return failure("REDIRECT_REJECTED");
 std::string cookies;
 if(op=="login"){
  auto keyMethod=e->GetMethodID(cls,"getHeaderFieldKey","(I)Ljava/lang/String;");
  auto valMethod=e->GetMethodID(cls,"getHeaderField","(I)Ljava/lang/String;");
  for(int i=1;i<80;++i){
   auto key=static_cast<jstring>(e->CallObjectMethod(conn,keyMethod,i));if(!key)break;
   const auto k=e->GetStringUTFChars(key,nullptr);std::string lower(k);e->ReleaseStringUTFChars(key,k);e->DeleteLocalRef(key);
   for(auto& c:lower)if(c>='A'&&c<='Z')c+=32;
   if(lower!="set-cookie")continue;
   auto value=static_cast<jstring>(e->CallObjectMethod(conn,valMethod,i));if(!value)continue;
   const auto v=e->GetStringUTFChars(value,nullptr);cookies+=v;cookies+='\n';e->ReleaseStringUTFChars(value,v);e->DeleteLocalRef(value);
   if(cookies.size()>8192)return failure("INVALID_RESPONSE");
  }
 }
 const auto read=e->GetMethodID(cls,status>=400?"getErrorStream":"getInputStream","()Ljava/io/InputStream;");
 connection.stream=e->CallObjectMethod(conn,read);
 if(e->ExceptionCheck()||!connection.stream)return result(e,status,"{}",cookies);
 auto streamClass=e->GetObjectClass(connection.stream);auto readMethod=e->GetMethodID(streamClass,"read","([B)I");
 auto buffer=e->NewByteArray(8192);std::string data;
 const auto start=std::chrono::steady_clock::now();
 for(;;){
  if(std::chrono::steady_clock::now()-start>std::chrono::seconds(30))return failure("TIMEOUT");
  const int n=e->CallIntMethod(connection.stream,readMethod,buffer);
  if(e->ExceptionCheck())return failure("NETWORK_ERROR");
  if(n<0)break;
  if(n==0)continue;
  if(data.size()+static_cast<size_t>(n)>plan->max_response)return failure("RESPONSE_TOO_LARGE");
  auto at=data.size();data.resize(at+static_cast<size_t>(n));
  e->GetByteArrayRegion(buffer,0,n,reinterpret_cast<jbyte*>(data.data()+at));
 }
 return result(e,status,data,cookies);
}
