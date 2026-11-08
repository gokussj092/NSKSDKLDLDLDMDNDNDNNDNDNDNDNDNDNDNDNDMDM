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
static unsigned columns(const std::string& s){
    unsigned result=0;
    for(size_t at=0;at<s.size();){
        const auto c=static_cast<unsigned char>(s[at]);
        const bool bullet=c==0xe2&&static_cast<unsigned char>(s[at+1])==0x80&&static_cast<unsigned char>(s[at+2])==0xa2;
        result+=c<128||bullet?1:2;at+=c<128?1:(c<0xe0?2:(c<0xf0?3:4));
    }
    return result;
}
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
    Document multilingual("{\"消息\":\"地地地最后字符\",\"ñ\":\"مرحبا\"}");
    assert(line(multilingual,1)=="  \"消息\": \"地地地最后字符\",");
    assert(line(multilingual,2)=="  \"ñ\": \"مرحبا\"");
    assert(nested.findNext("city",0,false)==2);
    assert(nested.findNext("LAST",0,false)==9);
    assert(nested.findNext("non-existent",0,false)==-1);
    assert(nested.findNext("CITY",0,false)==2);
    assert(secrets.findNext("FICTIONAL_ONLY",0,true)==-1);
    assert(secrets.findNext("FICTIONAL_ONLY",0,false)==2);
    assert(secrets.findNext("password",0,true)==4);
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
