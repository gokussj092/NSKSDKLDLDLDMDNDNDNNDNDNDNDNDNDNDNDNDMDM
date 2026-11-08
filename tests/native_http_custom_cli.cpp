#include "../android/app/src/main/cpp/spdecode_http_custom.h"
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
// Host-only differential test harness. All secrets are passed over stdin,
// never argv/environment/logs. This harness is not included in the APK.
namespace {
std::string take(size_t maximum){
    unsigned char length[4];
    if(!std::cin.read(reinterpret_cast<char*>(length),4))throw std::runtime_error("FRAME_SHORT");
    uint32_t n=(static_cast<uint32_t>(length[0])<<24)|
        (static_cast<uint32_t>(length[1])<<16)|(static_cast<uint32_t>(length[2])<<8)|length[3];
    if(n>maximum)throw std::runtime_error("FRAME_LIMIT");
    std::string value(n,'\0');
    if(n&&!std::cin.read(&value[0],static_cast<std::streamsize>(n)))
        throw std::runtime_error("FRAME_SHORT");
    return value;
}
}
int main(){
    try{
        auto pw=take(4096);
        auto hwid=take(128);
        auto bytes=take(4*1024*1024);
        std::vector<unsigned char> input(bytes.begin(),bytes.end());
        auto result=spdecode::offline::decodeHttpCustom(input,pw,hwid);
        std::cout<<result;
        std::fill(pw.begin(),pw.end(),0);
        return 0;
    }catch(const std::exception& error){
        // Reference fixtures only; never print file contents or credentials.
        std::cerr<<"ERROR:"<<error.what()<<"\n";
        return 2;
    }
}