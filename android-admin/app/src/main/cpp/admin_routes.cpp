#include "admin_routes.h"
#include <array>
namespace spdecode::admin {
namespace {
struct Route { std::string_view id; const char* path; const char* method; std::size_t max_body; };
constexpr std::array routes{
    Route{"login", "/api/admin/login", "POST", 2048},
    Route{"logout", "/api/admin/logout", "POST", 256},
    Route{"access", "/api/admin/access", "GET", 0},
    Route{"session", "/api/admin/session", "GET", 0},
    Route{"users", "/api/admin/users", "GET", 0},
    Route{"user_detail", "/api/admin/users", "GET", 0},
    Route{"staff", "/api/admin/staff", "GET", 0},
    Route{"roles", "/api/admin/staff-roles", "GET", 0},
    Route{"audit", "/api/admin/staff-audit", "GET", 0},
    Route{"support", "/api/admin/support", "GET", 0},
    Route{"store", "/api/admin/store", "GET", 0},
    Route{"gifts", "/api/admin/gifts", "GET", 0},
    Route{"notifications", "/api/admin/notifications", "GET", 0},
    Route{"observability", "/api/admin/observability", "GET", 0},
    Route{"reports", "/api/admin/reports", "GET", 0}
};
constexpr bool ascii_alnum(unsigned char c) {return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9');}
std::string encode(std::string_view s) {
    constexpr char hex[]="0123456789ABCDEF"; std::string out;
    for(unsigned char c:s){if(ascii_alnum(c)||c=='-'||c=='_'||c=='.'||c=='~')out+=static_cast<char>(c);else{out+='%';out+=hex[c>>4];out+=hex[c&15];}} return out;
}
bool id_ok(std::string_view s){if(s.size()<8||s.size()>80)return false;for(unsigned char c:s)if(!ascii_alnum(c)&&c!='_'&&c!='-')return false;return true;}
}
std::optional<Plan> plan(std::string_view operation,std::string_view query,int page,std::size_t body_size){
    for(const auto& r:routes){
        if(r.id!=operation)continue;
        if(body_size>r.max_body || (r.max_body!=0&&body_size==0))return std::nullopt;
        std::string path(r.path);
        if(operation=="users"){
            if(page<0||page>1000||query.size()>320)return std::nullopt;
            for(unsigned char c:query)if(c<32||c==127)return std::nullopt;
            path+="?page="+std::to_string(page)+"&q="+encode(query);
        }else if(operation=="user_detail"){
            if(page!=0||!id_ok(query))return std::nullopt;
            path+="?id="+encode(query);
        }else if(!query.empty()||page!=0)return std::nullopt;
        return Plan{path,r.method,8u*1024u*1024u};
    }
    return std::nullopt;
}
}
