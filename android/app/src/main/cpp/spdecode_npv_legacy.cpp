#include "spdecode_npv_legacy.h"
#include "spdecode_npv_crypto.h"
#include "spdecode_npv_whitebox.h"
#include <algorithm>
#include <string>
namespace spdecode::offline {
std::string decodeNpvLegacy(const std::vector<unsigned char>& data){
    using namespace npv;
    need(data.size()>16&&data.size()<=4u*1024u*1024u,"NPV_LEGACY_INVALID_SIZE");
    size_t start=0;
    if(data.size()>=8&&std::equal(data.begin(),data.begin()+8,"NPVTSUB1"))start=8;
    else if(data.size()>=5&&std::equal(data.begin(),data.begin()+5,"NPVT1"))start=5;
    else throw Error("NPV_LEGACY_UNSUPPORTED_HEADER");
    std::string contents(data.begin()+start,data.end());
    const auto first=contents.find(',');
    need(first!=std::string::npos,"NPV_LEGACY_INVALID_STRUCTURE");
    const auto end=contents.find(',',first+1);
    std::string encoded=contents.substr(first+1,end==std::string::npos?
                                             std::string::npos:end-first-1);
    encoded.erase(std::remove_if(encoded.begin(),encoded.end(),
            [](unsigned char c){return c==' '||c=='\n'||c=='\r'||c=='\t';}),
                  encoded.end());
    need(!encoded.empty()&&encoded.size()<=8u*1024u*1024u,"NPV_LEGACY_BASE64_LIMIT");
    for(char& c:encoded){
        if(c=='-')c='+';
        else if(c=='_')c='/';
        need((c>='A'&&c<='Z')||(c>='a'&&c<='z')||
             (c>='0'&&c<='9')||c=='+'||c=='/'||c=='=',"NPV_LEGACY_BAD_BASE64");
    }
    const auto pad=encoded.find('=');
    if(pad!=std::string::npos)
        need(pad>=encoded.size()-2&&encoded.size()%4==0&&
             std::all_of(encoded.begin()+pad,encoded.end(),
                         [](char c){return c=='=';}),"NPV_LEGACY_BAD_BASE64");
    encoded.append((4-encoded.size()%4)%4,'=');
    Bytes cipher(encoded.size()*3/4+4);
    size_t decodedLength=0;
    need(mbedtls_base64_decode(cipher.data(),cipher.size(),&decodedLength,
         reinterpret_cast<const unsigned char*>(encoded.data()),encoded.size())==0,
         "NPV_LEGACY_BAD_BASE64");
    cipher.resize(decodedLength);
    need(cipher.size()>16,"NPV_LEGACY_INVALID_CIPHERTEXT");
    Bytes iv=slice(cipher,0,16),plain(cipher.size()-16);
    for(size_t offset=16;offset<cipher.size();offset+=16){
        const Bytes stream=legacyBlock(iv);
        const size_t n=std::min<size_t>(16,cipher.size()-offset);
        for(size_t i=0;i<n;i++)
            plain[offset-16+i]=static_cast<unsigned char>(cipher[offset+i]^stream[i]);
        for(int j=15;j>=0;j--){
            iv[j]=static_cast<unsigned char>(iv[j]+1);
            if(iv[j]!=0)break;
        }
    }
    json result=parse(plain);
    need(result.is_object()||result.is_array(),"NPV_LEGACY_INVALID_DOCUMENT");
    return result.dump(2,' ',false,json::error_handler_t::strict)+"\n";
}
} // namespace spdecode::offline
