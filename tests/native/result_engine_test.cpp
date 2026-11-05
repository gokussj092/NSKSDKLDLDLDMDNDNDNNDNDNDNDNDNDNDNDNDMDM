#include "result_engine.h"
#include <cassert>
#include <iostream>
#include <random>
#include <string>
using spdecode_result::Document;
static bool rejects(const std::string& s){try{Document d(s);return false;}catch(const std::exception&){return true;}}
int main(){
    for(int count:{8000,20000,50000}){
        std::string raw="[\r\n";for(int i=0;i<count;++i){if(i)raw+=",\r\n";raw+="{\"id\":"+std::to_string(i)+",\"name\":\"demo🌎\"}";}raw+="\r\n]";
        Document d(raw);assert(d.node(0).count==static_cast<unsigned>(count));
        for(int offset=0;offset<count;offset+=64){const auto page=d.page(0,offset,64,false);assert(page.size()<65536);assert(page.find("\"rows\":[")!=std::string::npos);}
        std::string output;for(size_t offset=0;offset<d.bytes();offset+=65536)output+=d.original(offset,65536);assert(output==raw);
        std::cout<<"rows="<<count<<" nodes="<<d.nodes()<<" original_bytes="<<d.bytes()<<" export_equal=true\n";
    }
    Document duplicate("{\"x\":1,\"x\":2,\"pass\\u0077ord\":\"fictional-sensitive\",\"private_key\":{\"part\":\"fictional-key\"}}");
    assert(duplicate.node(0).count==4);assert(duplicate.page(0,0,64,true).find("fictional-sensitive")==std::string::npos);
    assert(duplicate.page(4,0,64,true).find("fictional-key")==std::string::npos);
    assert(duplicate.page(0,0,64,false).find("fictional-sensitive")!=std::string::npos);
    Document mixed("Name: demo\r\nPassword: fictional\r\nlast line");assert(mixed.node(0).count==3);assert(mixed.page(0,0,64,true).find("fictional")==std::string::npos);
    Document whitespace("  \r\nlast\r\n");assert(whitespace.node(0).count==3);assert(whitespace.value(1,0,16,false).find("  ")!=std::string::npos);
    Document emptyKey("{\"\":1}");assert(emptyKey.page(0,0,64,false).find("\"hasKey\":true")!=std::string::npos);
    std::string controls="[";for(int i=0;i<64;++i){if(i)controls+=',';controls+='"';for(int c=0;c<256;++c)controls+="\\u0001";controls+='"';}controls+=']';
    Document bounded(controls);assert(bounded.page(0,0,64,false).size()<65536);
    Document longValue("{\"v\":\""+std::string(200000,'z')+"🌎\"}");assert(longValue.value(1,0,4096,false).size()<8192);
    for(const auto& bad:{"{","[1,]","{\"a\":}","{\"a\":01}","{\"a\":1.}","{\"a\":NaN}","{\"a\":\"\\ud800\"}","{}[]"})assert(rejects(bad));
    assert(rejects(std::string("{\"a\":\"")+char(0xc0)+char(0x80)+"\"}"));
    for(int depth:{1,10,50,200}){Document deep(std::string(depth,'[')+"0"+std::string(depth,']'));assert(deep.nodes()==static_cast<size_t>(depth+1));}
    assert(rejects(std::string(201,'[')+"0"+std::string(201,']')));
    std::mt19937 rng(7);for(int i=0;i<5000;++i){std::string random;for(unsigned n=rng()%2048;n;--n)random+=static_cast<char>(rng()%256);try{Document d(random);assert(d.page(-1,0,1,true).size()<65536);}catch(const std::exception&) {}}
    std::cout<<"negative_utf8_depth_mask_duplicate_and_fuzz=PASS\n";
}
