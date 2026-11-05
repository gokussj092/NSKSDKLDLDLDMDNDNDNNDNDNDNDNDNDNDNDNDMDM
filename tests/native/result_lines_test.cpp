#include "result_engine.h"
#include <cassert>
#include <iostream>
#include <string>
using spdecode_result::Document;
static unsigned number(const std::string& s,const std::string& key){return static_cast<unsigned>(std::stoul(s.substr(s.find(key)+key.size())));}
static std::string text(const std::string& response){
    std::string out;size_t at=response.find("\"text\":\"")+8;
    while(at<response.size()){
        char c=response[at++];if(c=='"')return out;
        if(c!='\\'){out+=c;continue;}
        c=response[at++];
        if(c=='u'){assert(response.substr(at,2)=="00");out+=static_cast<char>(std::stoul(response.substr(at,4),nullptr,16));at+=4;}
        else if(c=='n')out+='\n';else if(c=='r')out+='\r';else if(c=='t')out+='\t';else out+=c;
    }
    assert(false);return {};
}
static unsigned columns(const std::string& s){unsigned result=0;for(unsigned char c:s)if((c&0xc0)!=0x80)result+=c>=0xf0?2:1;return result;}
static std::string line(const Document& doc,int row,bool mask=false){
    std::string out;unsigned column=0;
    while(true){
        const auto window=doc.lineWindow(row,static_cast<int>(column),127,mask);
        const auto part=text(window);const auto start=number(window,"\"column\":");
        if(part.empty())break;
        assert(start==column);out+=part;column=start+columns(part);
        if(column>=number(window,"\"columns\":"))break;
    }
    return out;
}
int main(){
    Document nested("{\"nested\":{\"city\":\"LA\",\"a\":[1,true,null]},\"end\":\"LAST\"}");
    const std::string expected[]={"{","  \"nested\": {","    \"city\": \"LA\",","    \"a\": [","      1,","      true,","      null","    ]","  },","  \"end\": \"LAST\"","}"};
    assert(nested.lines()==11);
    for(int i=0;i<11;++i)assert(line(nested,i)==expected[i]);
    // Full long keys and 200 KB scalar, including a surrogate pair at a window boundary.
    const std::string key(3500,'k'),value=std::string(121,'x')+"🌎"+std::string(200000,'z')+"LAST_CHARACTER";
    Document longLine("{\""+key+"\":\""+value+"\"}");
    assert(longLine.lines()==3);assert(line(longLine,1)=="  \""+key+"\": \""+value+"\"");
    const auto end=longLine.lineWindow(1,static_cast<int>(longLine.columns())-16,32,false);
    assert(text(end).find("LAST_CHARACTER")!=std::string::npos);
    // A viewport starting inside the emoji includes the whole code point.
    Document emoji("[\""+std::string(123,'a')+"🌎TAIL\"]");
    assert(text(emoji.lineWindow(1,127,2,false))=="🌎T");
    Document secrets("{\"private_key\":{\"part\":\"FICTIONAL_ONLY\"},\"password\":\"SECRET\",\"ok\":42}");
    assert(line(secrets,2,true)=="    \"part\": \"••••••••\"");
    assert(line(secrets,4,true)=="  \"password\": \"••••••••\",");
    assert(line(secrets,2,false).find("FICTIONAL_ONLY")!=std::string::npos);
    assert(line(secrets,5,true)=="  \"ok\": 42");
    Document empty("{\"a\":[],\"b\":{}}");
    assert(empty.lines()==6);assert(line(empty,2)=="  ],");
    Document duplicate("{\"x\":1,\"x\":2}");assert(line(duplicate,1)=="  \"x\": 1,");assert(line(duplicate,2)=="  \"x\": 2");
    for(int count:{8000,20000,50000}){
        std::string raw="[";for(int i=0;i<count;++i){if(i)raw+=',';raw+="{\"id\":"+std::to_string(i)+"}";}raw+=']';
        Document doc(raw);assert(doc.lines()==static_cast<size_t>(3*count+2));
        assert(line(doc,3*count-1)=="    \"id\": "+std::to_string(count-1));
        assert(line(doc,3*count)=="  }");assert(line(doc,3*count+1)=="]");
        std::string output;for(size_t offset=0;offset<doc.bytes();offset+=65536)output+=doc.original(offset,65536);assert(raw==output);
        std::cout<<"continuous_rows="<<doc.lines()<<" last_id="<<count-1<<" original_equal=true\n";
    }
    for(int depth:{1,50,200}){Document deep(std::string(depth,'[')+"0"+std::string(depth,']'));assert(deep.lines()==static_cast<size_t>(depth*2+1));assert(line(deep,depth)==std::string(depth*2,' ')+"0");}
    for(auto args: {std::pair<int,int>{-1,0},{0,-1},{11,0}}){try{nested.lineWindow(args.first,args.second,32,false);assert(false);}catch(const std::exception&){}}
    std::cout<<"full_lines_long_keys_long_values_unicode_mask_depth_random_access=PASS\n";
}
