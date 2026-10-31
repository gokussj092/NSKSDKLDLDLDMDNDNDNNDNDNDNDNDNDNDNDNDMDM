#include "spdecode_runtime_guard.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace spdecode {
namespace {
std::string readBounded(const char* path,std::size_t limit){
    std::ifstream stream(path,std::ios::binary);
    if(!stream)return {};
    std::string content;
    char buffer[4096];
    while(stream && content.size()<limit){
        const auto n=static_cast<std::streamsize>(
            std::min<std::size_t>(sizeof(buffer),limit-content.size()));
        stream.read(buffer,n);
        content.append(buffer,static_cast<std::size_t>(stream.gcount()));
    }
    return content;
}
}
int runtimeRiskFromProc(const std::string& status,const std::string& maps){
    int result=0;
    std::istringstream stream(status);
    std::string line;
    while(std::getline(stream,line)){
        if(line.compare(0,10,"TracerPid:")!=0)continue;
        std::istringstream number(line.substr(10));
        long pid=0;
        if(number>>pid && pid>0)result|=1;
        break;
    }
    // Check mapped native modules, not root state, emulator presence,
    // installed packages, filenames in storage, or the mere use of VPNs.
    // Deliberately narrow to avoid blocking legitimate user applications.
    std::string lower=maps;
    std::transform(lower.begin(),lower.end(),lower.begin(),
                   [](unsigned char c){return static_cast<char>(std::tolower(c));});
    static const char* markers[]={
        "/libfrida-gadget.so","/frida-gadget.so","/frida-agent-",
        "/libxposed_art.so","/libsubstrate.so","/libcydia_substrate.so"
    };
    for(const auto* marker:markers) {
        if(lower.find(marker)!=std::string::npos){result|=2;break;}
    }
    return result;
}
int runtimeRisk(){
#if defined(__linux__)
    return runtimeRiskFromProc(readBounded("/proc/self/status",64*1024),
                               readBounded("/proc/self/maps",2*1024*1024));
#else
    return 0;
#endif
}
} // namespace spdecode
