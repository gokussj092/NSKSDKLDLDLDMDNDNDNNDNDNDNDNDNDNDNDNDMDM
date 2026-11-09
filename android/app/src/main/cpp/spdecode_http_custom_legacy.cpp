#include "spdecode_http_custom_legacy.h"
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

namespace spdecode::offline {
namespace {
using Bytes=std::vector<unsigned char>;
using json=nlohmann::json;
constexpr size_t kLegacyInputMax=4u*1024u*1024u;
constexpr const char* keys[]={
"2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d",
"3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372",
"cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3",
"4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193",
"f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63",
"81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c",
"45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944",
"3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea"
};
constexpr const char* rstKeys[]={
"JN1k3YHc2.6_v235","JN1k3YHc_2.7_v71","JN1k3YHc2.7.ps69",
"JN1k3YHc2.7.6950","Jn1K3yHc2.8.ps08","Jn1K3yHc2.9.ps6c",
"Zk:L7>WKaiK*s9>D","!<f!&WIlM**R.B0X","b4a5opinx2uloec6"
};
constexpr const char* labels[]={
"payload","proxy","lockAllConfig","blockedByRoot","expiryTime",
"noteEnabled","notes","sshField","mobileDataAndLockProvider",
"unlockUserAndPass","ovpnConfig","ovpnUserAndPass","sni",
"unlockUserAndPass2","unknown14","blockedByHwid","cloudconfig",
"psiphon","name","blockArea","connectionMode","blockedByPassword",
"unknown22","extraSniffer","psiphon2","v2rayEnabled","v2rayConfig",
"version","slowdnsEnabled","slowdnsServer","slowdnsPublickey","dnsResolver"
};
constexpr std::array<unsigned char,20> jklOld={{
0xd5,0xd4,0xd3,0xd2,0xd1,0xd0,0xcf,0xce,0xcd,0xcc,
0xbd,0xbc,0xbb,0xba,0xb9,0xb8,0xb7,0xb6,0xb5,0xb4}};
constexpr std::array<unsigned char,20> jklNew={{
8,9,10,11,12,13,14,15,17,17,5,4,3,2,1,0,255,254,253,252}};
Bytes bytes(const std::string& v){return Bytes(v.begin(),v.end());}
std::string str(const Bytes& v){return std::string(v.begin(),v.end());}
int hexNibble(unsigned char c){
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    if(c>='A'&&c<='F')return c-'A'+10;
    return -1;
}
bool isHex(const std::string& text){
    return text.size()>=16&&std::all_of(text.begin(),text.end(),
      [](unsigned char c){return hexNibble(c)>=0;});
}
Bytes hexLoose(const std::string& input){
    std::string selected;
    for(unsigned char c:input)if(hexNibble(c)>=0)selected.push_back(static_cast<char>(c));
    if(selected.size()%2)selected="0"+selected;
    Bytes output;output.reserve(selected.size()/2);
    for(size_t i=0;i+1<selected.size();i+=2)
        output.push_back(static_cast<unsigned char>((hexNibble(selected[i])<<4)|hexNibble(selected[i+1])));
    return output;
}
Bytes b64(const std::string& text){
    std::string value=text;
    if(value.empty()||value.size()>kLegacyInputMax*2||value.size()%4==1)throw std::runtime_error("BAD_B64");
    value.append((4-value.size()%4)%4,'=');
    Bytes result(value.size()*3/4+4);
    size_t size=0;
    if(mbedtls_base64_decode(result.data(),result.size(),&size,
        reinterpret_cast<const unsigned char*>(value.data()),value.size())!=0)
        throw std::runtime_error("BAD_B64");
    result.resize(size);return result;
}
uint32_t le(const unsigned char* p){
    return static_cast<uint32_t>(p[0])|(static_cast<uint32_t>(p[1])<<8)|
      (static_cast<uint32_t>(p[2])<<16)|(static_cast<uint32_t>(p[3])<<24);
}
uint32_t rotl(uint32_t w,int n){return (w<<n)|(w>>(32-n));}
void q(std::array<uint32_t,16>& s,int a,int b,int c,int d){
    s[a]+=s[b];s[d]=rotl(s[d]^s[a],16);
    s[c]+=s[d];s[b]=rotl(s[b]^s[c],12);
    s[a]+=s[b];s[d]=rotl(s[d]^s[a],8);
    s[c]+=s[d];s[b]=rotl(s[b]^s[c],7);
}
Bytes chaCha8(const Bytes& input,const Bytes& key,const Bytes& nonce){
    if(key.size()!=32||nonce.size()!=8||input.size()>kLegacyInputMax)
        throw std::runtime_error("BAD_CHACHA");
    std::array<uint32_t,16> s{};
    s[0]=0x61707865;s[1]=0x3320646e;s[2]=0x79622d32;s[3]=0x6b206574;
    for(int i=0;i<8;i++)s[i+4]=le(key.data()+i*4);
    s[14]=le(nonce.data());s[15]=le(nonce.data()+4);
    Bytes out(input.size());
    uint64_t counter=1;
    for(size_t offset=0;offset<input.size();offset+=64){
        s[12]=static_cast<uint32_t>(counter);
        s[13]=static_cast<uint32_t>(counter>>32);
        auto state=s;
        for(int round=0;round<10;round++){
            q(state,0,4,8,12);q(state,1,5,9,13);
            q(state,2,6,10,14);q(state,3,7,11,15);
            q(state,0,5,10,15);q(state,1,6,11,12);
            q(state,2,7,8,13);q(state,3,4,9,14);
        }
        for(int i=0;i<16;i++)state[i]+=s[i];
        const size_t count=std::min<size_t>(64,input.size()-offset);
        for(size_t j=0;j<count;j++)
            out[offset+j]=static_cast<unsigned char>(input[offset+j]^
                ((state[j/4]>>(8*(j%4)))&255));
        counter++;
    }
    return out;
}
Bytes nonceStatic(){return Bytes(8,0xdb);}
std::string abc(const std::string& cipher,const Bytes& key,const Bytes& nonce=nonceStatic()){
    try{
        Bytes input=hexLoose(cipher);
        if(input.size()<=16)return "";
        input.resize(input.size()-16); // Legacy tag is not authenticated by exporter.
        return str(chaCha8(input,key,nonce));
    }catch(...){return "";}
}
std::string aesRst(const std::string& value){
    try{
        Bytes processed=bytes(value);
        for(size_t i=0;i<processed.size();i++)processed[i]^=static_cast<unsigned char>((i%20)+2);
        Bytes encrypted=b64(str(processed));
        if(encrypted.empty()||encrypted.size()%16)return "";
        for(const char* key:rstKeys){
            mbedtls_aes_context aes;mbedtls_aes_init(&aes);
            Bytes output(encrypted.size());
            int rc=mbedtls_aes_setkey_dec(&aes,reinterpret_cast<const unsigned char*>(key),128);
            for(size_t pos=0;rc==0&&pos<encrypted.size();pos+=16)
                rc=mbedtls_aes_crypt_ecb(&aes,MBEDTLS_AES_DECRYPT,encrypted.data()+pos,output.data()+pos);
            mbedtls_aes_free(&aes);
            if(rc!=0||output.empty())continue;
            size_t padding=output.back();
            if(padding<1||padding>16||padding>output.size())continue;
            bool correct=true;
            for(size_t i=0;i<padding;i++)if(output[output.size()-i-1]!=padding)correct=false;
            if(!correct)continue;
            output.resize(output.size()-padding);
            auto text=str(output);
            if(text.find("[splitConfig]")!=std::string::npos)return text;
        }
    }catch(...){}
    return "";
}
std::string jkl(const std::string& token,bool isNew){
    if(token.empty())return token;
    try{
        Bytes v=b64(token);
        const auto& key=isNew?jklNew:jklOld;
        for(size_t i=0;i<v.size();i++){
            unsigned char d=v[i],k=key[i%20];
            v[i]=static_cast<unsigned char>((((d^255)&0xca)|(d&0x35))^
                (((k^255)&0xca)|(k&0x35)));
        }
        return str(b64(str(v)));
    }catch(...){return token;}
}
bool printable(const std::string& value,bool strict=false){
    if(value.empty())return false;
    if(value.size()<4)return true;
    size_t count=0;
    for(unsigned char c:value){
        if(c>=32||c==9||c==10||c==13)count++;
    }
    return static_cast<double>(count)/value.size()>(strict?0.90:0.80);
}
std::string field(const std::string& token,const Bytes& nonce){
    if(token.empty()||token=="true"||token=="false"||token=="lifeTime"||
       token=="[splitPsiphon][splitPsiphon]"||token.front()=='<')return token;
    std::vector<Bytes> candidates;
    // Python's HCDecryptor cleans separators/non-hex characters BEFORE
    // recognizing a hexadecimal encrypted field. The previous port only
    // handled an uninterrupted raw hex token.
    const auto loose=hexLoose(token);
    if(loose.size()>16)candidates.push_back(loose);
    // Historical exports may store binary ciphertext as Latin-1 characters
    // inside UTF-8 JSON. Python tries Latin-1 bytes before the UTF-8 bytes.
    if(token.size()>16){
        Bytes latin;
        latin.reserve(token.size());
        bool valid=true;
        for(size_t i=0;i<token.size();){
            const unsigned char lead=static_cast<unsigned char>(token[i++]);
            if(lead<128){latin.push_back(lead);continue;}
            if((lead==0xc2||lead==0xc3)&&i<token.size()){
                const unsigned char next=static_cast<unsigned char>(token[i++]);
                if(next>=0x80&&next<=0xbf){
                    latin.push_back(static_cast<unsigned char>(((lead&3)<<6)|(next&63)));
                    continue;
                }
            }
            valid=false;break;
        }
        if(valid&&latin.size()>16&&latin!=bytes(token))candidates.push_back(std::move(latin));
        candidates.push_back(bytes(token));
    }
    for(const auto& data:candidates){
        if(data.size()<=16)continue;
        Bytes sealed=data;sealed.resize(sealed.size()-16);
        for(const char* hexkey:keys){
            try{
                auto trial=str(chaCha8(sealed,hexLoose(hexkey),nonce));
                for(bool useNew:{true,false}){
                    auto next=jkl(trial,useNew);
                    if(next!=trial&&printable(next))return next;
                }
                const bool marker=trial.find("HTTP")!=std::string::npos||
                    trial.find('@')!=std::string::npos||trial.find(':')!=std::string::npos||
                    trial.find('{')!=std::string::npos;
                const bool alnum=!trial.empty()&&std::all_of(trial.begin(),trial.end(),
                    [](unsigned char c){return std::isalnum(c)!=0;});
                if((printable(trial,true)&&marker)||alnum)return trial;
            }catch(...){}
        }
    }
    for(bool useNew:{true,false}){
        auto trial=jkl(token,useNew);
        if(trial!=token&&printable(trial))return trial;
    }
    return token;
}
std::vector<std::string> split(const std::string& input,const std::string& sep){
    std::vector<std::string> result;size_t begin=0;
    while(true){
        size_t where=input.find(sep,begin);
        if(where==std::string::npos){result.push_back(input.substr(begin));break;}
        result.push_back(input.substr(begin,where-begin));begin=where+sep.size();
        if(result.size()>1024)throw std::runtime_error("SPLIT_LIMIT");
    }
    return result;
}
std::string safeValue(const json& obj,const char* key){
    if(!obj.is_object()||!obj.contains(key)||obj.at(key).is_null())return "";
    const auto& v=obj.at(key);
    if(v.is_string())return v.get<std::string>();
    if(v.is_boolean())return v.get<bool>()?"True":"False";
    return v.dump();
}
std::string z3a(const std::string& text){
    const std::regex pattern("(-?[0-9]+)\\.(-?[0-9]+)");
    std::string result;
    size_t count=static_cast<size_t>(std::distance(
        std::sregex_iterator(text.begin(),text.end(),pattern),std::sregex_iterator()));
    if(count>512)return "";
    for(auto it=std::sregex_iterator(text.begin(),text.end(),pattern);
        it!=std::sregex_iterator();++it){
        try{
            auto left=std::stoll((*it)[1].str())-static_cast<long long>(count);
            auto pow=std::stoll((*it)[2].str())-static_cast<long long>(count);
            if(pow<0||pow>62)continue;
            auto divider=1ll<<pow;
            auto quotient=left/divider;
            if(left<0&&left%divider)quotient--;
            result.push_back(static_cast<char>((quotient%256+256)%256));
        }catch(...){}
    }
    return result;
}
// Historic HTTP Custom SSH credentials can arrive encoded as pairs of
// Unicode Braille glyphs. Mirror HTTPCUSTOM.py's alphabet before handling the
// numeric z3a wrapper. This is not a guess-based decryption fallback.
std::string unbraille(const std::string& raw){
    static const std::string alphabet=
        u8"⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏⠟⠗⠎⠞⠥⠧⠺⠭⠽⠵⠼⠁⠼⠃⠼⠉⠼⠙⠼⠑⠼⠋⠼⠛⠼⠊⠼⠚";
    // Every glyph is exactly three bytes of well-formed U+28xx UTF-8.
    if(raw.size()<3||raw.size()%3!=0)return raw;
    if(alphabet.find(raw.substr(0,3))==std::string::npos)return raw;
    std::vector<unsigned char> output;
    output.reserve(raw.size()/6);
    for(size_t i=0;i+5<raw.size();i+=6){
        const auto first=alphabet.find(raw.substr(i,3));
        const auto second=alphabet.find(raw.substr(i+3,3));
        if(first==std::string::npos||second==std::string::npos)return raw;
        const size_t a=first/3,b=second/3;
        output.push_back(static_cast<unsigned char>((a*16+b)&255));
    }
    // Python returns the original encrypted field when UTF-8 decoding fails.
    try{
        const auto decoded=str(output);
        // nlohmann JSON strings are strict UTF-8 during serialization.
        (void)json(decoded).dump();
        return decoded;
    }catch(...){return raw;}
}
std::string credentials(const std::string& input,bool ssh){
    if(input.empty())return input;
    const std::string clear=ssh?unbraille(input):input;
    // Reverse only recognized legacy numeric wrappers; preserve unrecognized
    // (including braille) rather than inventing incorrect credentials.
    if(ssh){
        auto at=clear.find('@');
        if(at==std::string::npos)return clear;
        auto colon=clear.find(':',at+1);
        if(colon==std::string::npos)return clear;
        const auto username=clear.substr(at+1,colon-at-1),password=clear.substr(colon+1);
        const auto user=z3a(username),pw=z3a(password);
        return clear.substr(0,at+1)+(user.empty()?username:user)+":"+(pw.empty()?password:pw);
    }
    const auto colon=input.find(':');
    if(colon==std::string::npos)return input;
    const auto username=input.substr(0,colon),password=input.substr(colon+1);
    const auto user=z3a(username),pw=z3a(password);
    return (user.empty()?username:user)+":"+(pw.empty()?password:pw);
}
bool decodeCarrier(const Bytes& bytes,json& result){
    const Bytes xorKey=hexLoose("e382e4b8adc386f09f9293");
    Bytes source=bytes;
    // Original bot treats binary as UTF-8 followed by Latin1. The safe
    // decoder tries the logical original first, then one UTF-8/Latin1 pass.
    for(int pass=0;pass<2;pass++){
        Bytes xorData(source.size());
        for(size_t i=0;i<source.size();i++)
            xorData[i]=static_cast<unsigned char>(source[i]^xorKey[i%xorKey.size()]);
        const auto outer=abc(str(xorData),hexLoose(keys[5]));
        if(!outer.empty()&&outer[0]=='{'){
            json obj=json::parse(outer,nullptr,false);
            if(obj.is_object()){
                json cfg=obj.value("cfg",json::object());
                bool newFormat=cfg.is_object()&&cfg.contains("content");
                json protections=json::object();
                std::string cipher,sep;
                std::string h,pa,pr,ar;
                if(newFormat){
                    h=safeValue(obj,"b");if(h.empty())h=safeValue(cfg,"b");
                    ar=safeValue(obj,"f");if(ar.empty())ar=safeValue(cfg,"f");
                    if(!h.empty())protections["hwid"]=h;
                    if(!ar.empty())protections["area"]=ar;
                    cipher=safeValue(cfg,"content");sep="[splitConfig]";
                }else{
                    json a=obj.value("a",json::object());
                    h=abc(safeValue(a,"bb"),hexLoose(keys[7]));
                    pa=abc(safeValue(obj,"e"),hexLoose(keys[7]));
                    ar=abc(safeValue(a,"fe"),hexLoose(keys[7]));
                    pr=abc(safeValue(a,"ed"),hexLoose(keys[7]));
                    if(!h.empty())protections["hwid"]=h;
                    if(!pa.empty())protections["password"]=pa;
                    if(!ar.empty())protections["area"]=ar;
                    if(!pr.empty())protections["provider"]=pr;
                    cipher=safeValue(obj,"xy");if(cipher.empty())cipher=safeValue(a,"xy");
                    sep=safeValue(obj,"uv");if(sep.empty())sep=safeValue(a,"uv");
                }
                if(!cipher.empty()&&!sep.empty()){
                    Bytes nonce=nonceStatic();
                    std::string derived;
                    if(!h.empty()&&pa.empty()&&pr.empty()&&ar.empty())derived=h+h;
                    else derived=pa+h+pr+ar;
                    const auto limit=std::min<size_t>(8,derived.size());
                    for(size_t i=0;i<limit;i++)nonce[i]=static_cast<unsigned char>(derived[i]);
                    std::string clear;
                    if(newFormat){
                        clear=aesRst(cipher);
                        if(clear.empty()){
                            for(const char* k:keys){
                                auto trial=abc(cipher,hexLoose(k));
                                if(trial.find(sep)!=std::string::npos){
                                    clear=std::move(trial);break;
                                }
                            }
                        }
                    }else clear=abc(cipher,hexLoose(keys[1]));
                    if(!clear.empty()&&clear.find(sep)!=std::string::npos){
                        json config=json::object();
                        auto sections=split(clear,sep);
                        for(size_t i=0;i<sections.size();i++){
                            if(i==22||i==24)continue;
                            auto value=sections[i];
                            if(value.empty())continue;
                            if(newFormat)value=field(value,nonce);
                            else {
                                if(isHex(value))value=abc(value,hexLoose(keys[7]),nonce);
                                value=jkl(value,false);
                            }
                            if(i==7)value=credentials(value,true);
                            if(i==11)value=credentials(value,false);
                            const std::string garbage="88a05e8772eac3e5703e0cd26c6e6f23de72fb09f7ee5a43283d1681f19d";
                            size_t where=0;
                            while((where=value.find(garbage,where))!=std::string::npos)
                                value.erase(where,garbage.size());
                            if(value.empty()||isHex(value))continue;
                            const std::string label=i<32?labels[i]:"field_"+std::to_string(i);
                            config[label]=value;
                        }
                        result={{"Protections",protections},{"Config",config}};
                        return true;
                    }
                }
            }
        }
        // UTF-8 to Latin-1 for carrier data (one pass).
        Bytes converted;converted.reserve(source.size());
        bool valid=true;
        for(size_t i=0;i<source.size();){
            unsigned char c=source[i++];
            if(c<128){converted.push_back(c);continue;}
            if((c==0xc2||c==0xc3)&&i<source.size()){
                auto b=source[i++];
                if(b>=0x80&&b<=0xbf){converted.push_back(((c&3)<<6)|(b&63));continue;}
            }
            valid=false;break;
        }
        if(!valid||converted==source)break;
        source=std::move(converted);
    }
    return false;
}
}
bool decodeLegacyHttpCustom(const std::vector<unsigned char>& raw,std::string& result){
    if(raw.empty()||raw.size()>kLegacyInputMax)return false;
    try{
        json decoded;
        if(decodeCarrier(raw,decoded)){
            result=decoded.dump(2,' ',false,json::error_handler_t::strict)+"\n";
            return true;
        }
    }catch(...){}
    return false;
}
} // namespace spdecode::offline
