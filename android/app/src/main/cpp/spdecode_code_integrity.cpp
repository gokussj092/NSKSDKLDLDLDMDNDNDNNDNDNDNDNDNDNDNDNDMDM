#include "spdecode_code_integrity.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <string>
#include <vector>
#if defined(__linux__)
#include <fcntl.h>
#include <link.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#endif

namespace spdecode {
#if defined(__linux__)
namespace {
constexpr std::size_t kMaxCode=32U*1024U*1024U;
struct Mapping {
    std::uintptr_t start,end;
    unsigned long long offset,inode;
    unsigned devMajor,devMinor;
    std::string path,perms;
};
struct Inspection {
    std::uintptr_t anchor;
    const std::vector<Mapping>* maps;
    CodeIntegrity result=CodeIntegrity::Unknown;
};
// Address-based DSO selection, independent of the basename or ABI.
void anchor() {}
int inspect(dl_phdr_info* info,std::size_t,void* data){
    auto& state=*static_cast<Inspection*>(data);
    bool owns=false;
    for(unsigned i=0;i<info->dlpi_phnum;++i){
        const auto& p=info->dlpi_phdr[i];
        const auto begin=info->dlpi_addr+p.p_vaddr;
        if(p.p_type==PT_LOAD && state.anchor>=begin && state.anchor-begin<p.p_memsz)owns=true;
    }
    if(!owns)return 0;
    std::size_t checked=0;
    for(unsigned i=0;i<info->dlpi_phnum;++i){
        const auto& p=info->dlpi_phdr[i];
        if(p.p_type!=PT_LOAD || !(p.p_flags&PF_X))continue;
        if((p.p_flags&PF_W) || !(p.p_flags&PF_R))return 1;
        if(p.p_filesz>kMaxCode-checked)return 1;
        auto cursor=static_cast<std::uintptr_t>(info->dlpi_addr+p.p_vaddr);
        const std::uintptr_t end=cursor+static_cast<std::uintptr_t>(p.p_filesz);
        if(end<cursor)return 1;
        while(cursor<end){
            const auto it=std::find_if(state.maps->begin(),state.maps->end(),[&](const Mapping& m){
                return cursor>=m.start && cursor<m.end;
            });
            if(it==state.maps->end())return 1;
            if(it->perms[0]!='r' || it->perms[1]=='w' || it->perms[2]!='x'){
                state.result=CodeIntegrity::Changed;return 1;
            }
            if(it->path.empty() || it->path[0]!='/' || !it->inode)return 1;
            const int fd=open(it->path.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
            if(fd<0)return 1;
            struct Close {int fd;~Close(){close(fd);}} closeFile{fd};
            struct stat st{};
            if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) ||
               static_cast<unsigned long long>(st.st_ino)!=it->inode ||
               major(st.st_dev)!=it->devMajor || minor(st.st_dev)!=it->devMinor)return 1;
            const auto finish=std::min(end,it->end);
            auto offset=it->offset+(cursor-it->start);
            if(offset>static_cast<unsigned long long>(std::numeric_limits<off_t>::max()) ||
               offset+finish-cursor>static_cast<unsigned long long>(st.st_size))return 1;
            unsigned char bytes[4096];
            while(cursor<finish){
                const auto n=std::min<std::size_t>(sizeof(bytes),finish-cursor);
                if(pread(fd,bytes,n,static_cast<off_t>(offset))!=static_cast<ssize_t>(n))return 1;
                if(std::memcmp(bytes,reinterpret_cast<const void*>(cursor),n)!=0){
                    state.result=CodeIntegrity::Changed;return 1;
                }
                cursor+=n;offset+=n;checked+=n;
            }
        }
    }
    if(checked)state.result=CodeIntegrity::Match;
    return 1;
}
}
#endif
CodeIntegrity verifyOwnExecutable(){
#if defined(__linux__)
    std::ifstream input("/proc/self/maps");
    if(!input)return CodeIntegrity::Unknown;
    std::vector<Mapping> maps;
    std::string line;
    std::size_t total=0;
    while(std::getline(input,line)){
        total+=line.size()+1;
        if(total>2U*1024U*1024U)return CodeIntegrity::Unknown;
        unsigned long long start=0,end=0,offset=0,inode=0;
        unsigned a=0,b=0;char perms[5]{};int count=0;
        if(std::sscanf(line.c_str(),"%llx-%llx %4s %llx %x:%x %llu %n",
            &start,&end,perms,&offset,&a,&b,&inode,&count)!=7 || !count || start>=end)
            return CodeIntegrity::Unknown;
        if(start>std::numeric_limits<std::uintptr_t>::max() || end>std::numeric_limits<std::uintptr_t>::max())
            return CodeIntegrity::Unknown;
        maps.push_back({static_cast<std::uintptr_t>(start),static_cast<std::uintptr_t>(end),
            offset,inode,a,b,line.substr(static_cast<std::size_t>(count)),perms});
    }
    if(input.bad())return CodeIntegrity::Unknown;
    Inspection state{reinterpret_cast<std::uintptr_t>(&anchor),&maps,CodeIntegrity::Unknown};
    dl_iterate_phdr(inspect,&state);
    return state.result;
#else
    return CodeIntegrity::Unknown;
#endif
}
} // namespace spdecode
