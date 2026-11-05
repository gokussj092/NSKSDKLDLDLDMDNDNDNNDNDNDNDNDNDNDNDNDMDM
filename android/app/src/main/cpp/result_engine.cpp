#include "result_engine.h"
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <utility>

namespace spdecode_result {
namespace {
[[noreturn]] void invalid(){throw std::runtime_error("RESULT_INDEX_INVALID");}
bool credential(std::string key){
    for(char& c:key)if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');
    for(const char* s:{"password","passwd","passphrase","mypass","credential","privatekey","private_key","apisecret","accesstoken","refreshtoken","authtoken","apitoken","secretkey","sshpass"})if(key.find(s)!=std::string::npos)return true;
    return false;
}
void utf8(const std::string& text){
    for(size_t i=0;i<text.size();){
        const auto c=static_cast<unsigned char>(text[i++]);if(c<128)continue;
        int n;uint32_t cp,min;
        if(c>=0xc2&&c<=0xdf){n=1;cp=c&31U;min=0x80;}
        else if(c>=0xe0&&c<=0xef){n=2;cp=c&15U;min=0x800;}
        else if(c>=0xf0&&c<=0xf4){n=3;cp=c&7U;min=0x10000;}else invalid();
        if(text.size()-i<static_cast<size_t>(n))invalid();
        for(int j=0;j<n;++j){const auto b=static_cast<unsigned char>(text[i++]);if((b&0xc0)!=0x80)invalid();cp=(cp<<6)|(b&63U);}
        if(cp<min||cp>0x10ffff||(cp>=0xd800&&cp<=0xdfff))invalid();
    }
}
void appendUtf8(std::string& s,uint32_t c){
    if(c<128)s.push_back(static_cast<char>(c));
    else if(c<2048){s.push_back(static_cast<char>(0xc0|(c>>6)));s.push_back(static_cast<char>(0x80|(c&63)));}
    else if(c<65536){s.push_back(static_cast<char>(0xe0|(c>>12)));s.push_back(static_cast<char>(0x80|((c>>6)&63)));s.push_back(static_cast<char>(0x80|(c&63)));}
    else{s.push_back(static_cast<char>(0xf0|(c>>18)));s.push_back(static_cast<char>(0x80|((c>>12)&63)));s.push_back(static_cast<char>(0x80|((c>>6)&63)));s.push_back(static_cast<char>(0x80|(c&63)));}
}
unsigned hex(char c){if(c>='0'&&c<='9')return static_cast<unsigned>(c-'0');if(c>='a'&&c<='f')return static_cast<unsigned>(c-'a'+10);if(c>='A'&&c<='F')return static_cast<unsigned>(c-'A'+10);invalid();}
std::string quoted(const std::string& s){
    std::string out="\"";const char* digits="0123456789abcdef";
    for(unsigned char c:s){if(c=='"'||c=='\\'){out+='\\';out+=static_cast<char>(c);}else if(c<32){out+="\\u00";out+=digits[c>>4];out+=digits[c&15];}else out+=static_cast<char>(c);}return out+'"';
}
const char* name(Kind k){switch(k){case Kind::Object:return "object";case Kind::Array:return "array";case Kind::String:return "string";case Kind::Number:return "number";case Kind::Boolean:return "boolean";case Kind::Null:return "null";case Kind::Text:return "text";}return "null";}
bool container(Kind k){return k==Kind::Object||k==Kind::Array;}
}
Document::Document(std::string source):source_(std::move(source)){
    if(source_.empty()||source_.size()>MaxBytes)invalid();
    utf8(source_);parse();indexLines();
}
Document::~Document(){volatile char* p=source_.empty()?nullptr:&source_[0];for(size_t i=0;i<source_.size();++i)p[i]=0;}
const Node& Document::node(int id)const{if(id<0||static_cast<size_t>(id)>=nodes_.size())invalid();return nodes_[static_cast<size_t>(id)];}
int Document::add(Node item){
    if(nodes_.size()>=MaxNodes)invalid();
    int id=static_cast<int>(nodes_.size());
    if(item.parent>=0){auto& p=nodes_[static_cast<size_t>(item.parent)];item.sensitive=item.sensitive||p.sensitive;if(p.last>=0)nodes_[static_cast<size_t>(p.last)].next=id;else p.first=id;p.last=id;++p.count;}
    nodes_.push_back(std::move(item));return id;
}
void Document::parse(){
    size_t pos=0;const size_t length=source_.size();
    auto skip=[&](){while(pos<length&&(source_[pos]==' '||source_[pos]=='\r'||source_[pos]=='\n'||source_[pos]=='\t'))++pos;};
    auto string=[&](bool decode){
        if(pos>=length||source_[pos++]!='"')invalid();
        std::string out;
        while(pos<length){unsigned char c=static_cast<unsigned char>(source_[pos++]);if(c=='"')return out;if(c<32)invalid();
            if(c!='\\'){if(decode){out+=static_cast<char>(c);if(out.size()>4096)invalid();}continue;}
            if(pos>=length)invalid();
            char e=source_[pos++];
            if(e=='u'){
                auto unit=[&](){if(length-pos<4)invalid();uint32_t v=0;for(int j=0;j<4;++j)v=(v<<4)|hex(source_[pos++]);return v;};
                uint32_t cp=unit();if(cp>=0xd800&&cp<=0xdbff){if(length-pos<6||source_[pos++]!='\\'||source_[pos++]!='u')invalid();const auto low=unit();if(low<0xdc00||low>0xdfff)invalid();cp=0x10000+((cp-0xd800)<<10)+low-0xdc00;}else if(cp>=0xdc00&&cp<=0xdfff)invalid();
                if(decode)appendUtf8(out,cp);
            }else{const std::string escapes="\"\\/bfnrt",values="\"\\/\b\f\n\r\t";const auto at=escapes.find(e);if(at==std::string::npos)invalid();if(decode)out+=values[at];}
            if(out.size()>4096)invalid();
        }invalid();
    };
    skip();
    if(pos==length||(source_[pos]!='{'&&source_[pos]!='[')){
        // Mixed legacy text is indexed by physical lines, with no normalization.
        Node root;root.kind=Kind::Array;root.end=static_cast<uint32_t>(length);const int parent=add(std::move(root));
        pos=0;
        while(pos<length){const size_t start=pos;while(pos<length&&source_[pos]!='\r'&&source_[pos]!='\n')++pos;Node line;line.kind=Kind::Text;line.parent=parent;line.start=static_cast<uint32_t>(start);line.end=static_cast<uint32_t>(pos);line.sensitive=true;add(std::move(line));if(pos<length&&source_[pos++]=='\r'&&pos<length&&source_[pos]=='\n')++pos;}
        if(source_.back()=='\r'||source_.back()=='\n'){Node line;line.kind=Kind::Text;line.parent=parent;line.start=line.end=static_cast<uint32_t>(length);line.sensitive=true;add(std::move(line));}
        return;
    }
    struct Frame{int id;int stage;};std::vector<Frame> stack;
    auto value=[&](int parent,std::string key){
        skip();if(pos>=length)invalid();Node n;n.parent=parent;n.hasKey=parent>=0&&nodes_[static_cast<size_t>(parent)].kind==Kind::Object;n.key=std::move(key);n.sensitive=credential(n.key);n.start=static_cast<uint32_t>(pos);const char c=source_[pos];
        if(c=='{'||c=='['){n.kind=c=='{'?Kind::Object:Kind::Array;++pos;const int id=add(std::move(n));if(stack.size()>=MaxDepth)invalid();stack.push_back({id,0});return;}
        if(c=='"'){n.kind=Kind::String;string(false);}
        else if(c=='t'&&source_.compare(pos,4,"true")==0){n.kind=Kind::Boolean;pos+=4;}
        else if(c=='f'&&source_.compare(pos,5,"false")==0){n.kind=Kind::Boolean;pos+=5;}
        else if(c=='n'&&source_.compare(pos,4,"null")==0){n.kind=Kind::Null;pos+=4;}
        else{
            n.kind=Kind::Number;if(source_[pos]=='-')++pos;if(pos>=length)invalid();
            if(source_[pos]=='0')++pos;else{if(source_[pos]<'1'||source_[pos]>'9')invalid();while(pos<length&&source_[pos]>='0'&&source_[pos]<='9')++pos;}
            if(pos<length&&source_[pos]=='.'){++pos;const size_t start=pos;while(pos<length&&source_[pos]>='0'&&source_[pos]<='9')++pos;if(pos==start)invalid();}
            if(pos<length&&(source_[pos]=='e'||source_[pos]=='E')){++pos;if(pos<length&&(source_[pos]=='+'||source_[pos]=='-'))++pos;const size_t start=pos;while(pos<length&&source_[pos]>='0'&&source_[pos]<='9')++pos;if(pos==start)invalid();}
        }
        n.end=static_cast<uint32_t>(pos);
        // Opaque escaped strings may contain nested JSON credentials. Until a
        // nested projection is requested, hide the whole opaque scalar in privacy mode.
        if(n.kind==Kind::String&&std::find(source_.begin()+n.start,source_.begin()+static_cast<std::ptrdiff_t>(pos),'\\')!=source_.begin()+static_cast<std::ptrdiff_t>(pos))n.sensitive=true;
        add(std::move(n));
    };
    value(-1,{});
    while(!stack.empty()){
        skip();if(pos>=length)invalid();const int id=stack.back().id;const bool object=node(id).kind==Kind::Object;const char close=object?'}':']';
        if(source_[pos]==close){if(stack.back().stage==2)invalid();++pos;nodes_[static_cast<size_t>(id)].end=static_cast<uint32_t>(pos);stack.pop_back();continue;}
        if(stack.back().stage==1){if(source_[pos++]!=',')invalid();stack.back().stage=2;skip();}
        std::string key;if(object){key=string(true);if(key.size()>4096)invalid();skip();if(pos>=length||source_[pos++]!=':')invalid();}
        stack.back().stage=1;value(id,std::move(key));
    }
    skip();if(pos!=length)invalid();
}
std::string Document::value(int id,int offset,int limit,bool mask)const{
    const auto& n=node(id);if(offset<0||limit<1||limit>4096||container(n.kind))invalid();
    const size_t total=n.end-n.start;if(static_cast<size_t>(offset)>total)invalid();
    if(mask&&n.sensitive)return "{\"value\":\"••••••••\",\"offset\":0,\"next\":0,\"totalBytes\":0}";
    size_t start=n.start+static_cast<size_t>(offset),end=std::min<size_t>(n.end,start+static_cast<size_t>(limit));
    if(start<n.end&&(static_cast<unsigned char>(source_[start])&0xc0)==0x80)invalid();
    while(end<n.end&&(static_cast<unsigned char>(source_[end])&0xc0)==0x80)--end;
    if(end==start&&end<n.end){end=start+1;while(end<n.end&&(static_cast<unsigned char>(source_[end])&0xc0)==0x80)++end;}
    return "{\"value\":"+quoted(source_.substr(start,end-start))+",\"offset\":"+std::to_string(offset)+",\"next\":"+std::to_string(end-n.start)+",\"totalBytes\":"+std::to_string(total)+"}";
}
std::string Document::row(int id,bool mask)const{
    const auto& n=node(id);std::string key=n.key;if(key.size()>256){key.resize(256);while(!key.empty()&&(static_cast<unsigned char>(key.back())&0xc0)==0x80)key.pop_back();if(!key.empty()&&static_cast<unsigned char>(key.back())>=0xc0)key.pop_back();key+="…";}
    const bool hidden=mask&&n.sensitive;
    return "{\"id\":"+std::to_string(id)+",\"key\":"+quoted(key)+",\"hasKey\":"+(n.hasKey?"true":"false")+",\"type\":"+quoted(name(n.kind))+",\"count\":"+std::to_string(n.count)+",\"hidden\":"+(hidden?"true":"false")+",\"slice\":"+(container(n.kind)?"null":value(id,0,256,mask))+"}";
}
std::string Document::page(int parent,int offset,int limit,bool mask)const{
    if(offset<0||limit<1||limit>64)invalid();
    std::string out="{\"rows\":[";int id;
    if(parent<0){if(offset!=0)invalid();id=0;}else{const auto& n=node(parent);if(!container(n.kind)||static_cast<uint32_t>(offset)>n.count)invalid();id=n.first;for(int i=0;i<offset&&id>=0;++i)id=node(id).next;}
    int count=0;while(id>=0&&count<limit){const auto item=row(id,mask);if(count&&out.size()+item.size()+1024>65536)break;if(count++)out+=',';out+=item;id=parent<0?-1:node(id).next;}
    return out+"],\"next\":"+std::to_string(offset+count)+",\"hasMore\":"+(id>=0?"true":"false")+"}";
}
std::string Document::original(size_t offset,size_t limit)const{if(offset>source_.size()||limit>65536)invalid();return source_.substr(offset,std::min(limit,source_.size()-offset));}
namespace {
// Conservative monospace cells keep wide fallback glyphs reachable horizontally.
// Privacy bullets use one cell; other non-ASCII code points reserve two cells.
uint32_t advanceColumn(const std::string& text,size_t& at){
    const auto c=static_cast<unsigned char>(text[at]);
    const bool bullet=c==0xe2&&static_cast<unsigned char>(text[at+1])==0x80&&static_cast<unsigned char>(text[at+2])==0xa2;
    at+=c<128?1:(c<0xe0?2:(c<0xf0?3:4));
    return c<128||bullet?1U:2U;
}
uint32_t width(const std::string& text){
    uint32_t columns=0;for(size_t at=0;at<text.size();)columns+=advanceColumn(text,at);return columns;
}
}
std::string Document::prefix(const Line& line)const{
    std::string result(line.depth*2,' ');
    const auto& n=node(line.id);
    if(!line.closing&&n.hasKey)result+=quoted(n.key)+": ";
    return result;
}
void Document::indexLines(){
    struct Pending{int id;uint32_t depth;bool closing;};
    std::vector<Pending> pending{{0,0,false}};
    while(!pending.empty()){
        const auto item=pending.back();pending.pop_back();const auto& n=node(item.id);
        Line line{item.id,item.depth,0,0,static_cast<uint32_t>(checkpoints_.size()),0,item.closing};
        const auto start=prefix(line);line.keyColumns=width(start);
        line.columns=line.keyColumns;
        if(item.closing||container(n.kind))++line.columns;
        else{
            size_t at=n.start;uint32_t column=0,counter=0;
            while(at<n.end){
                if(counter++%128==0)checkpoints_.push_back({static_cast<uint32_t>(at),column});
                column+=advanceColumn(source_,at);
            }
            line.columns+=column;
            line.checkpointCount=static_cast<uint32_t>(checkpoints_.size())-line.checkpointStart;
        }
        if((item.closing||!container(n.kind))&&n.next>=0)++line.columns;
        columns_=std::max(columns_,line.columns);lines_.push_back(line);
        if(!item.closing&&container(n.kind)){
            pending.push_back({item.id,item.depth,true});
            std::vector<int> children;
            for(int child=n.first;child>=0;child=node(child).next)children.push_back(child);
            for(auto it=children.rbegin();it!=children.rend();++it)pending.push_back({*it,item.depth+1,false});
        }
    }
}
std::string Document::lineWindow(int index,int column,int count,bool mask)const{
    if(index<0||static_cast<size_t>(index)>=lines_.size()||column<0||count<1||count>2048)invalid();
    const auto& line=lines_[static_cast<size_t>(index)];const auto& n=node(line.id);
    const uint64_t endColumn=static_cast<uint64_t>(column)+static_cast<unsigned>(count);
    std::string text;uint32_t first=static_cast<uint32_t>(column);
    auto append=[&](const std::string& data,size_t at,size_t end,uint32_t base){
        while(at<end&&base<endColumn){
            const size_t begin=at;const auto cells=advanceColumn(data,at);
            if(static_cast<uint64_t>(base)+cells>static_cast<unsigned>(column)){
                if(text.empty())first=base;
                text.append(data,begin,at-begin);
            }
            base+=cells;
        }
    };
    const auto start=prefix(line);append(start,0,start.size(),0);
    uint32_t after=line.keyColumns;
    if(line.closing||container(n.kind)){
        const std::string bracket(1,n.kind==Kind::Object?(line.closing?'}':'{'):(line.closing?']':'['));
        append(bracket,0,1,after++);
    }else if(mask&&n.sensitive){
        const std::string hidden="\"••••••••\"";append(hidden,0,hidden.size(),after);after+=10;
    }else{
        size_t at=n.start;uint32_t offset=0;
        if(line.checkpointCount&&column>static_cast<int>(after)){
            const auto begin=checkpoints_.begin()+line.checkpointStart;
            const auto end=begin+line.checkpointCount;
            auto found=std::upper_bound(begin,end,static_cast<uint32_t>(column)-after,
                [](uint32_t target,const Checkpoint& cp){return target<cp.column;});
            if(found!=begin){--found;at=found->byte;offset=found->column;}
        }
        append(source_,at,n.end,after+offset);
        after=line.columns-(n.next>=0?1U:0U);
    }
    if((line.closing||!container(n.kind))&&n.next>=0){const std::string comma=",";append(comma,0,1,after);++after;}
    return "{\"text\":"+quoted(text)+",\"column\":"+std::to_string(first)+
        ",\"columns\":"+std::to_string(after)+",\"valueColumn\":"+std::to_string(line.keyColumns)+
        ",\"type\":"+quoted(name(n.kind))+"}";
}

}

