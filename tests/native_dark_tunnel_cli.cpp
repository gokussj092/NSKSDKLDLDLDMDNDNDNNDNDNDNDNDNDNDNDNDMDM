#include "../android/app/src/main/cpp/spdecode_dark_tunnel.h"
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
int main(int argc,char** argv){
    try{
        const std::string input(std::istreambuf_iterator<char>(std::cin),{});
        const std::vector<unsigned char> bytes(input.begin(),input.end());
        if(argc==2 && std::string(argv[1])=="--identify")
            std::cout<<(spdecode::offline::isDarkTunnelEnvelope(bytes)?"true":"false")<<"\n";
        else std::cout<<spdecode::offline::decodeDarkTunnel(bytes)<<"\n";
        return 0;
    }catch(const std::exception& error){
        std::cerr<<error.what()<<"\n";
        return 2;
    }
}
