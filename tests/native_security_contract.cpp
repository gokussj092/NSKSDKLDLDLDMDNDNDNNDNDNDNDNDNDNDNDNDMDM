// Independent protocol contract checks for the native proof and Play nonce.
// No Android service or private key is accessed by these host tests.
#include "../android/app/src/main/cpp/spdecode_security.h"
#include <cassert>
#include <iostream>
#include <string>
#include <stdexcept>
int main(){
    const std::string data="ciphertext";
    const std::string bearer="header.payload.signature";
    const std::string nonce(32,'A');
    const auto text=spdecode::formatProof(5,"1.1.24",
        reinterpret_cast<const unsigned char*>(data.data()),data.size(),
        bearer,"1793380000",nonce);
    const auto digestBody=spdecode::sha256Hex(
        reinterpret_cast<const unsigned char*>(data.data()),data.size());
    const auto digestBearer=spdecode::sha256Hex(
        reinterpret_cast<const unsigned char*>(bearer.data()),bearer.size());
    assert(text=="SPDECODE-POP-V2\nPOST\n5\n1.1.24\n1793380000\n"+nonce+"\n"+
           digestBearer+"\n"+digestBody);
    assert(spdecode::sha256Hex(nullptr,0)==
       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const auto generated=spdecode::prepareProof(5,"1.1.24",
        reinterpret_cast<const unsigned char*>(data.data()),data.size(),bearer);
    assert(generated.nonce.size()==32);
    assert(generated.message.find("SPDECODE-POP-V2\nPOST\n5\n")==0);
    const auto suffix=spdecode::makeAliasSuffix();
    assert(suffix.size()==8);
    assert(spdecode::validClassicChallenge(std::string(43,'A'),
        "11111111-1111-1111-1111-111111111111","v2"));
    assert(!spdecode::validClassicChallenge(std::string(42,'A'),
        "11111111-1111-1111-1111-111111111111","v2"));
    assert(!spdecode::validClassicChallenge(std::string(43,'A'),
        "11111111-1111-1111-1111-111111111111","v1"));
    assert(spdecode::validActionChallenge(std::string(43,'B'),
        "11111111-1111-1111-1111-111111111111",123));
    assert(!spdecode::validActionChallenge(std::string(43,'B'),
        "11111111-1111-1111-1111-111111111111",0));
    assert(spdecode::validPlayNonce(std::string(43,'C')));
    assert(!spdecode::validPlayNonce("bad token"));
    const auto play=spdecode::playNonce(std::string(43,'A'),
        "11111111-1111-1111-1111-111111111111",std::string(120,'B'));
    assert(play.size()==43);
    bool rejected=false;
    try{(void)spdecode::formatProof(3,"1.1.24",
        reinterpret_cast<const unsigned char*>(data.data()),data.size(),
        bearer,"1793380000",nonce);}
    catch(const std::exception&){rejected=true;}
    assert(rejected);
    std::cout<<"PASS native V2 proof and Integrity nonce protocol\n";
}
