#include "spdecode_runtime_guard.h"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#if defined(SPDECODE_ELF_GUARD)
#include "spdecode_code_integrity.h"
#endif

namespace spdecode {
namespace {
std::string readBounded(const char* path,std::size_t limit){
    std::ifstream stream(path,std::ios::binary);
    if(!stream)return {};
    std::string content;
    char buffer[4096];
    while(stream && content.size()<=limit){
        const auto n=static_cast<std::streamsize>(
            std::min<std::size_t>(sizeof(buffer),limit+1-content.size()));
        stream.read(buffer,n);
        content.append(buffer,static_cast<std::size_t>(stream.gcount()));
    }
    if(stream.bad() || content.size()>limit)return {};
    return content;
}
}
RuntimeEvidence runtimeEvidenceFromProc(const std::string& status,const std::string& maps){
    RuntimeEvidence result;
    std::istringstream stream(status);
    std::string line;
    while(std::getline(stream,line)){
        if(line.compare(0,10,"TracerPid:")!=0)continue;
        std::istringstream number(line.substr(10));
        std::string digits,extra;
        if(number>>digits && !(number>>extra) && !digits.empty() && digits.size()<=10 &&
           std::all_of(digits.begin(),digits.end(),[](unsigned char c){return std::isdigit(c);})){
            const auto pid=std::stoull(digits);
            if(pid<=static_cast<unsigned>(std::numeric_limits<int>::max())){
                result.evaluated|=StatusChecked;
                if(pid>0)result.signals|=Traced;
            }
        }
        break;
    }
    // Executable mappings of this process only. Names alone remain advisory.
    std::istringstream mappings(maps);
    bool any=false,malformed=false;
    while(std::getline(mappings,line)){
        if(line.empty())continue;
        std::istringstream fields(line);
        std::string range,perms,offset,rest;
        if(!(fields>>range>>perms>>offset) || range.find('-')==std::string::npos ||
           perms.size()!=4){malformed=true;continue;}
        any=true;
        if(perms[2]!='x')continue;
        std::getline(fields,rest);
        std::transform(rest.begin(),rest.end(),rest.begin(),
                       [](unsigned char c){return static_cast<char>(std::tolower(c));});
        static const char* markers[]={"/libfrida-gadget.so","/frida-gadget.so","/frida-agent-",
            "/libxposed_art.so","/libsubstrate.so","/libcydia_substrate.so"};
        for(const auto* marker:markers)
            if(rest.find(marker)!=std::string::npos){result.signals|=InstrumentationModule;break;}
    }
    if(any&&!malformed)result.evaluated|=MapsChecked;
    return result;
}
RuntimeEvidence runtimeEvidence(){
    const auto start=std::chrono::steady_clock::now();
    RuntimeEvidence result;
#if defined(__linux__)
    result=runtimeEvidenceFromProc(readBounded("/proc/self/status",64*1024),
                                   readBounded("/proc/self/maps",2*1024*1024));
#if defined(SPDECODE_ELF_GUARD)
    const auto code=verifyOwnExecutable();
    if(code!=CodeIntegrity::Unknown)result.evaluated|=CodeChecked;
    if(code==CodeIntegrity::Changed)result.signals|=CodeChanged;
#endif
#endif
    result.elapsedMicros=static_cast<std::uint64_t>(std::chrono::duration_cast<
        std::chrono::microseconds>(std::chrono::steady_clock::now()-start).count());
    return result;
}
std::string runtimeEvidenceJson(const RuntimeEvidence& e){
    return "{\"v\":1,\"signals\":"+std::to_string(e.signals)+",\"evaluated\":"+
        std::to_string(e.evaluated)+",\"elapsedUs\":"+
        std::to_string(std::min<std::uint64_t>(e.elapsedMicros,60000000))+"}";
}
int runtimeRiskFromProc(const std::string& status,const std::string& maps){
    return static_cast<int>(runtimeEvidenceFromProc(status,maps).signals);
}
int runtimeRisk(){return static_cast<int>(runtimeEvidence().signals);}
} // namespace spdecode
