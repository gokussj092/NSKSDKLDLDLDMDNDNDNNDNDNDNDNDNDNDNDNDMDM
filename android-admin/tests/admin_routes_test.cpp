#include "admin_routes.h"
#include <cassert>
#include <iostream>
using spdecode::admin::plan;
int main(){
    for(auto id:{"access","session","staff","roles","audit","support","store","gifts","notifications","observability","reports"}){
        auto p=plan(id,"",0,0);assert(p&&std::string(p->method)=="GET"&&p->path.rfind("/api/admin/",0)==0);assert(!plan(id,"",0,1));assert(!plan(id,"bad",0,0));
    }
    auto login=plan("login","",0,2048);assert(login&&std::string(login->method)=="POST");assert(!plan("login","",0,0));assert(!plan("login","",0,2049));
    assert(plan("logout","",0,2));assert(!plan("logout","",0,257));
    auto users=plan("users","a&x=#? /\xc3\xb1",3,0);assert(users&&users->path=="/api/admin/users?page=3&q=a%26x%3D%23%3F%20%2F%C3%B1");
    assert(plan("users","",0,0));assert(plan("users","",1000,0));assert(!plan("users","",1001,0));assert(!plan("users","",-1,0));assert(!plan("users","x\n",0,0));assert(!plan("users",std::string(321,'x'),0,0));
    assert(plan("user_detail","abc_1234",0,0));assert(!plan("user_detail","abc/1234",0,0));assert(!plan("user_detail","123",0,0));assert(!plan("user_detail","abc_1234",1,0));
    for(auto id:{"https://example.com","../login","maintenance","catalog-edition","support_write",""})assert(!plan(id,"",0,0));
    std::cout<<"PASS native route allowlist, methods, bounds, URL encoding and rejection of unauthorized route IDs\n";
}
