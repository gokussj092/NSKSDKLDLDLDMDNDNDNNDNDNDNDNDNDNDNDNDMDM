#include "spdecode_npv_whitebox.h"
#include "spdecode_npv_tables.h"
#include <zlib.h>
#include <array>
#include <cstdint>
#include <mutex>
#include <vector>

namespace spdecode::offline::npv {
namespace {
using State=std::array<unsigned char,16>;
constexpr std::array<int,16> order={{0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11}};
State permute(const State& s){
    State out{};
    for(size_t i=0;i<16;i++)out[i]=s[order[i]];
    return out;
}
uint32_t readBE(const unsigned char* p){
    return (static_cast<uint32_t>(p[0])<<24)|(static_cast<uint32_t>(p[1])<<16)|
           (static_cast<uint32_t>(p[2])<<8)|p[3];
}
unsigned char lookup(const unsigned char* table,size_t t,unsigned a,unsigned b){
    return table[t*256u+(a&15u)*16u+(b&15u)];
}
void combine(State& state,const unsigned char* xorTable,const unsigned char* wordTable){
    State next{};
    for(int col=0;col<4;col++){
        uint32_t w[4];
        for(int i=0;i<4;i++){
            const int index=col*4+i;
            w[i]=readBE(wordTable+index*1024+state[index]*4);
        }
        for(int row=0;row<4;row++){
            const int t=col*24+row*6;
            const int high=28-row*8,low=24-row*8;
            const unsigned a=lookup(xorTable,t,(w[0]>>high)&15,(w[1]>>high)&15);
            const unsigned b=lookup(xorTable,t+1,(w[2]>>high)&15,(w[3]>>high)&15);
            const unsigned c=lookup(xorTable,t+2,(w[0]>>low)&15,(w[1]>>low)&15);
            const unsigned d=lookup(xorTable,t+3,(w[2]>>low)&15,(w[3]>>low)&15);
            const unsigned hi=lookup(xorTable,t+4,a,b);
            const unsigned lo=lookup(xorTable,t+5,c,d);
            next[col*4+row]=static_cast<unsigned char>(hi<<4|lo);
        }
    }
    state=next;
}
Bytes finish(const State& state,const unsigned char* last){
    Bytes output(16);
    for(size_t i=0;i<16;i++)output[i]=last[i*256+state[i]];
    return output;
}
State stateFrom(const Bytes& input){
    need(input.size()==16,"NPV_WHITEBOX_BAD_BLOCK");
    State out{};std::copy(input.begin(),input.end(),out.begin());return out;
}
const Bytes& modern(){
    static Bytes expanded;
    static std::once_flag once;
    std::call_once(once,[](){
        expanded.resize(749569);
        uLongf n=static_cast<uLongf>(expanded.size());
        const int rc=uncompress(expanded.data(),&n,tables::kModernZlib,
                                static_cast<uLong>(tables::kModernZlibSize));
        need(rc==Z_OK&&n==expanded.size(),"NPV_MODERN_WHITEBOX_INVALID");
        need(hex(hash(expanded))==
            "35717e8267a115fbf474e3cd622066783feea21305457c840cabd57a73086f7d",
            "NPV_MODERN_WHITEBOX_HASH");
    });
    return expanded;
}
}
Bytes modernBlock(const Bytes& input){
    auto state=stateFrom(input);
    const auto& table=modern();
    const size_t rounds=table[0]-1;
    need(rounds==13,"NPV_MODERN_WHITEBOX_ROUNDS");
    const size_t first=1+rounds*24576;
    const size_t last=first+rounds*16384;
    const size_t second=last+4096;
    need(second+rounds*16384==table.size(),"NPV_MODERN_WHITEBOX_LAYOUT");
    for(size_t r=0;r<rounds;r++){
        state=permute(state);
        const auto* xorTable=table.data()+1+r*24576;
        combine(state,xorTable,table.data()+first+r*16384);
        combine(state,xorTable,table.data()+second+r*16384);
    }
    state=permute(state);
    return finish(state,table.data()+last);
}
Bytes v1Block(const Bytes& input,bool alternate){
    auto state=permute(stateFrom(input));
    combine(state,tables::kV1Xor,tables::kV1Ty);
    combine(state,tables::kV1Xor,tables::kV1Mbl);
    state=permute(state);
    return finish(state,alternate?tables::kV1FinalV2:tables::kV1Final);
}
Bytes legacyBlock(const Bytes& input){
    auto state=permute(stateFrom(input));
    combine(state,tables::kLegacyP2,tables::kLegacyP3);
    combine(state,tables::kLegacyP2,tables::kLegacyP5);
    state=permute(state);
    return finish(state,tables::kLegacyP4);
}
} // namespace spdecode::offline::npv
