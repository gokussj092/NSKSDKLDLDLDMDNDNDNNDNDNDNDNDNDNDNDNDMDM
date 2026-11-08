#include "../android/app/src/main/cpp/spdecode_http_injector.h"
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>
int main(){
    try{
        unsigned char length[4];
        if(!std::cin.read(reinterpret_cast<char*>(length),4))return 2;
        size_t size=static_cast<size_t>(length[0])<<24|static_cast<size_t>(length[1])<<16|
            static_cast<size_t>(length[2])<<8|length[3];
        if(size>4u*1024u*1024u)return 2;
        std::vector<unsigned char> raw(size);
        if(size&&!std::cin.read(reinterpret_cast<char*>(raw.data()),static_cast<std::streamsize>(size)))return 2;
        auto result=spdecode::offline::decodeHttpInjector(raw);
        std::cout<<result;
        std::fill(raw.begin(),raw.end(),0);
        return 0;
    }catch(const std::exception& e){
        std::cerr<<"ERROR:"<<e.what()<<'\n';
        return 2;
    }
}
