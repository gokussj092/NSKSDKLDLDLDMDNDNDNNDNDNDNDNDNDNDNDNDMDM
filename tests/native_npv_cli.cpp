#include "../android/app/src/main/cpp/spdecode_npv_signed.h"
#include "../android/app/src/main/cpp/spdecode_npv_legacy.h"
#include "../android/app/src/main/cpp/spdecode_npv_text.h"
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
namespace {
std::string readFrame(size_t maximum){
    unsigned char b[4];
    if(!std::cin.read(reinterpret_cast<char*>(b),4))throw std::runtime_error("FRAME_SHORT");
    const size_t size=(static_cast<size_t>(b[0])<<24)|(static_cast<size_t>(b[1])<<16)|
      (static_cast<size_t>(b[2])<<8)|static_cast<size_t>(b[3]);
    if(size>maximum)throw std::runtime_error("FRAME_LIMIT");
    std::string output(size,'\0');
    if(size&&!std::cin.read(&output[0],static_cast<std::streamsize>(size)))
        throw std::runtime_error("FRAME_SHORT");
    return output;
}
}
int main(){
    try{
        auto password=readFrame(4096);
        auto recipient=readFrame(16384);
        auto input=readFrame(4u*1024u*1024u);
        std::vector<unsigned char> raw(input.begin(),input.end());
        std::string clear;
        if(spdecode::offline::isNpvText(raw))
            clear=spdecode::offline::decodeNpvText(raw,password,recipient);
        else if(raw.size()>=4&&std::equal(raw.begin(),raw.begin()+4,"NPVS"))
            clear=spdecode::offline::decodeNpvSigned(raw,password,recipient);
        else
            clear=spdecode::offline::decodeNpvLegacy(raw);
        std::cout<<clear;
        std::fill(password.begin(),password.end(),0);
        std::fill(recipient.begin(),recipient.end(),0);
        return 0;
    }catch(const std::exception& ex){
        std::cerr<<"ERROR:"<<ex.what()<<"\n";
        return 2;
    }
}
