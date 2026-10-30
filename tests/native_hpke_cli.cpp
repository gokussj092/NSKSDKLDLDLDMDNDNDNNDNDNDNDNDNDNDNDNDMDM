// Host-only test tool. Never included in Android release artifacts.
#include "../android/app/src/main/cpp/spdecode_hpke.h"
#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
unsigned hexDigit(char c) {
    if(c>='0'&&c<='9')return unsigned(c-'0');
    if(c>='a'&&c<='f')return unsigned(c-'a'+10);
    if(c>='A'&&c<='F')return unsigned(c-'A'+10);
    throw std::runtime_error("bad hex");
}
std::vector<unsigned char> parse(const std::string& s) {
    if(s.size()%2)throw std::runtime_error("bad hex length");
    std::vector<unsigned char> out;
    for(size_t i=0;i<s.size();i+=2)
        out.push_back(static_cast<unsigned char>(hexDigit(s[i])*16+hexDigit(s[i+1])));
    return out;
}
std::string hex(const std::vector<unsigned char>& src){
    static const char alphabet[]="0123456789abcdef";
    std::string out;out.reserve(src.size()*2);
    for(unsigned char b:src){out.push_back(alphabet[b>>4]);out.push_back(alphabet[b&15]);}
    return out;
}
}
int main(int argc,char** argv) {
    try {
        if(argc!=3)throw std::runtime_error("usage: cli pinHex metadataJson");
        auto pinBytes=parse(argv[1]);
        if(pinBytes.size()!=40)throw std::runtime_error("pin must have 40 bytes");
        std::array<unsigned char,40> pin{};
        std::copy(pinBytes.begin(),pinBytes.end(),pin.begin());
        std::string json=argv[2];
        auto prepared=spdecode::hpkePrepare(
            6,std::vector<unsigned char>(json.begin(),json.end()),{},pin);
        std::cout<<hex(prepared.wire)<<std::endl;
        std::string reply;std::getline(std::cin,reply);
        const auto plaintext=spdecode::hpkeOpen(prepared.handle,200,prepared.wire,parse(reply));
        std::cout<<std::string(plaintext.begin(),plaintext.end())<<std::endl;
        return 0;
    }catch(const std::exception& e){
        std::cerr<<"NATIVE_HPKE_TEST_FAILED: "<<e.what()<<std::endl;
        return 1;
    }
}
