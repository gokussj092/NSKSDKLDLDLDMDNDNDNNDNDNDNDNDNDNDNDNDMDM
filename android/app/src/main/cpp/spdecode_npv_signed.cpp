#include "spdecode_npv_signed.h"
#include "spdecode_npv_crypto.h"
#include "spdecode_npv_whitebox.h"
#include <array>
#include <cstring>
#include <set>
#include <string>
#include <vector>
namespace spdecode::offline {
namespace {
using namespace npv;
constexpr size_t kMaxFile=4u*1024u*1024u;
bool same(const Bytes& a,const Bytes& b){
    if(a.size()!=b.size())return false;
    unsigned char mismatch=0;
    for(size_t i=0;i<a.size();i++)mismatch|=a[i]^b[i];
    return mismatch==0;
}
json jsonV1(const Bytes& rawData,const std::string& password,const std::string& recipient){
    need(rawData.size()>=89&&rawData.size()<=kMaxFile,"NPV_V1_BAD_SIZE");
    const auto headerSize=u32(rawData,5);
    need(headerSize>=64&&headerSize<=65536&&
         9ull+headerSize+16+16+64<=rawData.size(),"NPV_V1_BAD_HEADER");
    const Bytes header= slice(rawData,9,headerSize);
    const auto obj=parse(header);
    need(obj.is_object()&&obj.value("v",0)==1,"NPV_V1_BAD_HEADER");
    need(obj.contains("creator")&&obj["creator"].is_object(),"NPV_V1_CREATOR");
    const auto& creator=obj["creator"];
    need(creator.contains("pk")&&creator["pk"].is_string(),"NPV_V1_CREATOR");
    auto publicKey=unurl(creator["pk"].get<std::string>(),128);
    need(publicKey.size()==33,"NPV_V1_BAD_PUBLIC");
    if(creator.contains("fp")&&creator["fp"].is_string())
        need(same(unurl(creator["fp"].get<std::string>(),128),hash(publicKey)),
             "NPV_V1_FINGERPRINT");
    signature(rawData,publicKey);
    const size_t offset=9+headerSize;
    const Bytes nonce=slice(rawData,offset,12);
    const size_t bodyLength=u32(rawData,offset+12);
    need(bodyLength>=16&&offset+16+bodyLength+64==rawData.size(),"NPV_V1_BAD_BODY");
    const Bytes body=slice(rawData,offset+16,bodyLength);
    auto app=obj.value("appKey",json(nullptr));
    auto phrase=obj.value("passphrase",json(nullptr));
    auto recipients=obj.value("recipients",json(nullptr));
    const bool hasApp=app.is_object(),hasPhrase=phrase.is_object();
    const bool hasRecipient=recipients.is_array()&&!recipients.empty();
    Bytes dek;
    if(hasApp&&!hasPhrase&&!hasRecipient){
        need(password.empty()&&recipient.empty(),"NPV_INVALID_CREDENTIALS");
        need(app.value("kdf",std::string())=="wbaes-ctr-sha256"&&
             app.value("keyId",0)==1,"NPV_PROTECTION_UNSUPPORTED");
        auto salt=unurl(app.at("salt").get<std::string>());
        auto wrapped=unurl(app.at("wrap").get<std::string>());
        need(salt.size()==16&&wrapped.size()==60,"NPV_V1_BAD_DESCRIPTOR");
        for(bool alternate:{false,true}){
            Bytes pre=raw("npvtunnel/appkey/v1 ");
            append(pre,v1Block(salt,alternate));
            const Bytes kdk=hash(pre);
            try{
                dek=openChaCha(kdk,slice(wrapped,0,12),
                               slice(wrapped,12,48),salt);
                break;
            }catch(const Error&){ }
        }
        need(dek.size()==32,"NPV_PROTECTION_UNSUPPORTED");
    }else if(hasPhrase&&!hasApp&&!hasRecipient){
        need(recipient.empty(),"NPV_INVALID_CREDENTIALS");
        need(phrase.value("kdf",std::string())=="pbkdf2-hmac-sha256",
             "NPV_PROTECTION_UNSUPPORTED");
        need(!password.empty(),"PASSWORD_REQUIRED");
        const int64_t iter=phrase.at("iters").get<int64_t>();
        need(iter>=1&&iter<=10000000,"NPV_PBKDF2_LIMIT");
        auto salt=unurl(phrase.at("salt").get<std::string>());
        auto wrapped=unurl(phrase.at("wrap").get<std::string>());
        need(salt.size()>=8&&salt.size()<=64&&wrapped.size()==60,"NPV_V1_BAD_DESCRIPTOR");
        dek=openChaCha(pbkdf2(password,salt,static_cast<uint32_t>(iter)),
                       slice(wrapped,0,12),slice(wrapped,12,48),salt);
    }else if(hasRecipient&&!hasApp&&!hasPhrase){
        throw Error("NPV_RECIPIENT_V1_UNSUPPORTED"); // Recipient-mode v1 has no supported local unwrap.
    }else throw Error("NPV_PROTECTION_UNSUPPORTED");
    need(dek.size()==32,"NPV_INVALID_DOCUMENT_KEY");
    auto clear=openChaCha(dek,nonce,body,header);
    json parsed=parse(clear);
    need(parsed.is_object()||parsed.is_array(),"NPV_V1_INVALID_DOCUMENT");
    embedded(parsed);
    return parsed;
}
Bytes fieldKey(const Bytes& dek,const Bytes& context,const char* purpose,uint16_t id){
    Bytes info=raw("NPV-fields-v1/");
    append(info,purpose);append(info,"/");num16(info,id);
    return derive(dek,context,info);
}
json fieldDocument(const Bytes& body,const Bytes& dek,const Bytes& context){
    need(body.size()>=70&&body[0]=='N'&&body[1]=='P'&&body[2]=='F'&&
         body[3]==1&&same(slice(body,4,32),context),
         "NPV_INVALID_FIELD_DOCUMENT");
    const Bytes inventoryKey=fieldKey(dek,context,"inventory",0);
    const Bytes signedPart=slice(body,0,body.size()-32);
    const Bytes digest=mac(inventoryKey,signedPart);
    need(same(digest,slice(body,body.size()-32,32)),
         "NPV_FIELD_INVENTORY_INVALID");
    const size_t count=u16(body,36);
    need(count>=1,"NPV_EMPTY_FIELDS");
    size_t offset=38;uint16_t last=0;
    std::map<uint16_t,json> fields;
    for(size_t i=0;i<count;i++){
        need(offset+6<=body.size()-32,"NPV_FIELD_TRUNCATED");
        const uint16_t id=u16(body,offset);
        const uint32_t length=u32(body,offset+2);offset+=6;
        need(id>last&&length>=16&&length<=1048592&&
             length<=body.size()-32-offset,"NPV_INVALID_FIELD_ORDER");
        const Bytes sealed=slice(body,offset,length);offset+=length;
        Bytes aad=raw("NPV-fields-v1/record/");
        append(aad,context);num16(aad,id);num32(aad,length-16);
        const Bytes nonce(12);
        const Bytes clear=openChaCha(fieldKey(dek,context,"field",id),nonce,sealed,aad);
        fields.emplace(id,parse(clear));last=id;
    }
    need(offset==body.size()-32&&fields.count(65535),"NPV_FIELD_TRAILING");
    std::set<uint16_t> used;
    std::function<void(json&,int)> resolve=[&](json& node,int depth){
        need(depth<=128,"NPV_FIELD_DEPTH");
        if(node.is_object()){for(auto it=node.begin();it!=node.end();++it)resolve(it.value(),depth+1);}
        else if(node.is_array()){for(auto& item:node)resolve(item,depth+1);}
        else{
            need(node.is_number_integer()&&!node.is_boolean(),"NPV_INVALID_FIELD_REF");
            const int64_t ref=node.get<int64_t>();
            need(ref>=1&&ref<65535&&fields.count(static_cast<uint16_t>(ref)),
                 "NPV_INVALID_FIELD_REF");
            const json& scalar=fields.at(static_cast<uint16_t>(ref));
            need(!scalar.is_array()&&!scalar.is_object(),"NPV_INVALID_SCALAR");
            used.insert(static_cast<uint16_t>(ref));
            node=scalar;
        }
    };
    json document=fields.at(65535);
    resolve(document,0);
    need(used.size()+1==fields.size(),"NPV_UNREFERENCED_FIELD");
    need(document.is_object()&&document.contains("configs")&&
         document["configs"].is_array(),"NPV_MISSING_CONFIGS");
    return document;
}
struct ModernFrame {
    int version=0;
    unsigned mode=0;
    Bytes header,nonce,descriptor,body,publicKey,configId;
    size_t prefixEnd=0;
    std::vector<Bytes> records;
    Bytes version6salt;
};
ModernFrame inspect(const Bytes& input){
    need(input.size()>=89&&input.size()<=kMaxFile,"NPV_INVALID_SIZE");
    need(input.size()>=9&&input[0]=='N'&&input[1]=='P'&&
         input[2]=='V'&&input[3]=='S',"NPV_INVALID_MAGIC");
    ModernFrame frame;
    frame.version=input[4];
    need(frame.version==5||frame.version==6,"NPV_UNSUPPORTED_VERSION");
    size_t hlen=u32(input,5);
    need(hlen>=73&&hlen<=262144&&9+hlen+80<=input.size(),"NPV_INVALID_HEADER");
    frame.header=slice(input,9,hlen);
    auto& header=frame.header;
    need(header[0]==1&&(header[50]==0||header[50]==1||header[50]==2),
         "NPV_PROTECTION_UNSUPPORTED");
    frame.mode=header[50];
    size_t count=u16(header,51);
    need(count<=1024,"NPV_TOO_MANY_RECIPIENTS");
    size_t offset=53;
    std::set<Bytes> seen;
    for(size_t i=0;i<count;i++){
        auto record=slice(header,offset,125);
        need(!seen.count(slice(record,0,32))&&(record[32]==2||record[32]==3),
             "NPV_INVALID_RECIPIENT");
        seen.insert(slice(record,0,32));frame.records.push_back(std::move(record));
        offset+=125;
    }
    if(frame.version==6){
        frame.version6salt=slice(header,offset,16);
        offset+=16;
    }
    const size_t descLength=frame.mode==1?80:frame.mode==2?78:0;
    need(offset+descLength+4<=hlen&&(frame.mode!=0||count!=0),
         "NPV_INVALID_DESCRIPTOR");
    frame.descriptor=slice(header,offset,descLength);
    offset+=descLength;
    if(frame.mode==1){
        const auto iters=u32(frame.descriptor,0);
        need(iters>=600000&&iters<=10000000,"NPV_PBKDF2_LIMIT");
    }
    if(frame.mode==2)need(frame.descriptor[0]==0&&frame.descriptor[1]==2,
                          "NPV_PROTECTION_UNSUPPORTED");
    frame.prefixEnd=offset;
    const size_t metadataLength=u32(header,offset);
    need(metadataLength>=16&&offset+4+metadataLength==hlen,"NPV_INVALID_METADATA");
    const size_t end=9+hlen;
    frame.nonce=slice(input,end,12);
    const size_t bodyLength=u32(input,end+12);
    need(bodyLength>=70&&end+16+bodyLength+64==input.size(),
         "NPV_INVALID_BODY_LENGTH");
    frame.body=slice(input,end+16,bodyLength);
    frame.publicKey=slice(header,17,33);
    frame.configId=slice(header,1,16);
    signature(input,frame.publicKey); // Before requesting password or ECDH.
    return frame;
}
Bytes recipientDek(const Bytes& file,const ModernFrame& frame,
                   const std::string& identityJson){
    need(!identityJson.empty(),"PRIVATE_KEY_REQUIRED");
    need(identityJson.size()<=16384,"NPV_INVALID_CREDENTIALS");
    json identity=parse(raw(identityJson));
    need(identity.is_object()&&identity.value("schema",std::string())=="spdecode.npvs.recipient.v1"&&
         identity.value("curve",std::string())=="P-256","NPV_INVALID_RECIPIENT_ID");
    auto fingerprint=identity.value("fingerprint",std::string());
    need(fingerprint.size()==64,"NPV_INVALID_RECIPIENT_ID");
    Bytes fp;
    // Verify the identity's public key / fingerprint against this file.
    if(identity.value("kind",std::string())=="keypair"){
        const auto pub=unurl(identity.at("publicKey").get<std::string>(),128);
        need(pub.size()==33&&hex(hash(pub))==fingerprint,
             "NPV_INVALID_IDENTITY_FINGERPRINT");
        fp=hash(pub);
    }else if(identity.value("kind",std::string())=="agreement"){
        need(identity.value("source",std::string())=="captured"&&
             identity.value("fileSha256",std::string())==hex(hash(file)),
             "NPV_INVALID_AGREEMENT");
        fp.clear();
        for(size_t i=0;i<fingerprint.size();i+=2){
            const auto h=fingerprint.substr(i,2);
            fp.push_back(static_cast<unsigned char>(std::stoul(h,nullptr,16)));
        }
    }else throw Error("NPV_INVALID_RECIPIENT_ID");
    for(const auto& record:frame.records){
        if(!same(slice(record,0,32),fp))continue;
        Bytes sharedSecret;
        if(identity.value("kind",std::string())=="keypair"){
            const Bytes der=unurl(identity.at("privateKey").get<std::string>());
            sharedSecret=shared(der,slice(record,32,33));
        }else{
            const Bytes peer=unurl(identity.at("peer").get<std::string>(),128);
            need(same(peer,slice(record,32,33)),"NPV_RECIPIENT_MISMATCH");
            sharedSecret=unurl(identity.at("sharedSecret").get<std::string>(),128);
            need(sharedSecret.size()==32,"NPV_INVALID_AGREEMENT");
        }
        Bytes info=raw("NPVS-v1-wrap");append(info,frame.configId);
        const Bytes wrapKey=derive(sharedSecret,fp,info);
        Bytes dek=openGcm(wrapKey,slice(record,65,12),
                          slice(record,77,48),fp);
        if(frame.version==6){
            Bytes seed=raw("npvtunnel/appkey/v2 ");
            append(seed,modernBlock(frame.version6salt));
            append(seed,frame.configId);
            auto kdk=hash(seed);
            Bytes binding=raw("NPVS-v6/recipient-binding");
            append(binding,frame.configId);
            auto pad=derive(kdk,frame.version6salt,binding);
            for(size_t i=0;i<32;i++)dek[i]^=pad[i];
        }
        return dek;
    }
    throw Error("RECIPIENT_MISMATCH");
}
json modernDoc(const Bytes& file,const ModernFrame& frame,
               const std::string& password,const std::string& identity){
    Bytes dek;
    if(frame.mode==0){
        need(password.empty(),"NPV_INVALID_CREDENTIALS");
        dek=recipientDek(file,frame,identity);
    }else{
        need(identity.empty(),"NPV_INVALID_CREDENTIALS");
        need(frame.version==5,"NPV_PROTECTION_UNSUPPORTED");
        Bytes salt,wrapped,kdk;
        if(frame.mode==1){
            need(!password.empty(),"PASSWORD_REQUIRED");
            salt=slice(frame.descriptor,4,16);
            wrapped=slice(frame.descriptor,20,60);
            kdk=pbkdf2(password,salt,u32(frame.descriptor,0));
        }else{
            need(password.empty(),"NPV_INVALID_CREDENTIALS");
            salt=slice(frame.descriptor,2,16);
            wrapped=slice(frame.descriptor,18,60);
            Bytes content=raw("npvtunnel/appkey/v2 ");
            append(content,modernBlock(salt));append(content,frame.configId);
            kdk=hash(content);
        }
        dek=openChaCha(kdk,slice(wrapped,0,12),slice(wrapped,12,48),salt);
    }
    need(dek.size()==32,"NPV_INVALID_DOCUMENT_KEY");
    const Bytes prefix=slice(frame.header,0,frame.prefixEnd);
    const Bytes nonce=frame.nonce;
    const Bytes sealed=slice(frame.header,frame.prefixEnd+4,
                             frame.header.size()-frame.prefixEnd-4);
    const auto metadata=parse(openChaCha(derive(dek,nonce,raw("NPVS-v5/metadata")),
                                           nonce,sealed,prefix));
    need(metadata.is_object()&&metadata.contains("policy")&&metadata["policy"].is_object(),
         "NPV_INVALID_METADATA");
    const auto& policy=metadata["policy"];
    json sourcePolicy={
        {"onlyMobileNetwork",policy.value("onlyMobileNetwork",json(false))},
        {"attestationLevel",policy.value("attestationLevel",json(""))},
        {"expiresAt",policy.value("expiresAt",json(nullptr))},
        {"displayMessage",policy.value("displayMessage",json(""))},
        {"customServerMessage",policy.value("customServerMessage",json(""))}
    };
    if(policy.contains("configVersion")&&policy["configVersion"]!=json(0)&&
       !policy["configVersion"].is_null()&&policy["configVersion"]!=json(false))
        sourcePolicy["configVersion"]=policy["configVersion"];
    json creator={
        {"fp",url(hash(frame.publicKey))},
        {"pk",url(frame.publicKey)}
    };
    json source={
        {"v",frame.version},
        {"configId",url(frame.configId)},
        {"issuedAt",metadata.value("issuedAt",json(""))},
        {"creator",creator},
        {"policy",sourcePolicy},
        {"recipients",nullptr}
    };
    Bytes ctx=raw("NPVS-v"+std::to_string(frame.version)+"/source-fields-v1/");
    append(ctx,canonical(source));
    append(ctx,nonce);
    const Bytes context=hash(ctx);
    json document=fieldDocument(frame.body,dek,context);
    json output={{"metadata",metadata},{"document",document}};
    embedded(output);
    return output;
}
} // namespace
std::string decodeNpvSigned(const std::vector<unsigned char>& input,
                            const std::string& password,
                            const std::string& recipientJson){
    need(input.size()>=89&&input.size()<=kMaxFile&&
         input[0]=='N'&&input[1]=='P'&&input[2]=='V'&&input[3]=='S',
         "NPV_INVALID_INPUT");
    const int version=input[4];
    json result;
    if(version==1)result=jsonV1(input,password,recipientJson);
    else if(version==5||version==6){
        const auto frame=inspect(input);
        result=modernDoc(input,frame,password,recipientJson);
    }else throw Error("NPV_UNSUPPORTED_VERSION");
    return result.dump(2,' ',false,json::error_handler_t::strict)+"\n";
}
} // namespace spdecode::offline
