#include "../android/app/src/main/cpp/spdecode_hat_tunnel.h"
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
int main(){
    try {
        const std::string input(std::istreambuf_iterator<char>(std::cin),{});
        const std::vector<unsigned char> bytes(input.begin(),input.end());
        std::cout<<spdecode::offline::decodeHatTunnel(bytes)<<"\n";
        return 0;
    } catch(const std::exception& e){
        std::cerr<<e.what()<<"\n";
        return 2;
    }
}
