#include "../android/app/src/main/cpp/spdecode_catalog.h"
#include <mbedtls/base64.h>
#include <mbedtls/platform_util.h>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>
namespace {
std::vector<unsigned char> decode(std::string s) {
    for(char& c:s)if(c=='-')c='+';else if(c=='_')c='/';
    s.append((4-s.size()%4)%4,'=');
    std::vector<unsigned char> result(s.size());
    size_t n=0;
    if(mbedtls_base64_decode(result.data(),result.size(),&n,
        reinterpret_cast<const unsigned char*>(s.data()),s.size())!=0)
        throw std::runtime_error("invalid pkcs8");
    result.resize(n);
    return result;
}
}
int main(int argc,char** argv) {
    if(argc!=9)return 2;
    try {
        auto privateKey=decode(argv[1]);
        auto packed=spdecode::openCatalog(privateKey,argv[2],argv[3],
            argv[4],argv[5],argv[6],std::stoi(argv[7]),argv[8]);
        if(!privateKey.empty())mbedtls_platform_zeroize(privateKey.data(),privateKey.size());
        if(std::fwrite(packed.data(),1,packed.size(),stdout)!=packed.size())return 3;
        std::fflush(stdout);
        return 0;
    }catch(const std::exception&){return 1;}
}
