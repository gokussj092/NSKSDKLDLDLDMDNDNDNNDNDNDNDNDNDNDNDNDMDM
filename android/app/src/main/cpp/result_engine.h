#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace spdecode_result {
enum class Kind { Object, Array, String, Number, Boolean, Null, Text };
struct Node {
    uint32_t start=0,end=0,count=0;
    int parent=-1,first=-1,last=-1,next=-1;
    Kind kind=Kind::Null;
    bool sensitive=false,hasKey=false;
    std::string key;
};
class Document {
public:
    static constexpr size_t MaxBytes=32U*1024U*1024U,MaxNodes=200000,MaxDepth=200;
    explicit Document(std::string source);
    ~Document();
    Document(const Document&)=delete;
    size_t bytes()const{return source_.size();}
    size_t nodes()const{return nodes_.size();}
    const Node& node(int id)const;
    std::string page(int parent,int offset,int limit,bool mask)const;
    std::string value(int id,int offset,int limit,bool mask)const;
    std::string original(size_t offset,size_t limit)const;
private:
    std::string source_;
    std::vector<Node> nodes_;
    int add(Node item);
    void parse();
    std::string row(int id,bool mask)const;
};
}
