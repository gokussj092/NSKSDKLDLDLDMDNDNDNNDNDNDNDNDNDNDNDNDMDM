/**
 * SP-DECODE V2 encrypted-body profile, HPKE RFC 9180 base mode:
 * DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM.
 * Only the challenge bootstrap (public metadata) is unencrypted.
 */
import {createPrivateKey,createPublicKey,diffieHellman,createHmac,createHash,createDecipheriv,createCipheriv} from "node:crypto";
const P8=Buffer.from("302e020100300506032b656e04220420","hex");
const SPKI=Buffer.from("302a300506032b656e032100","hex");
const KEM=Buffer.from("4b454d0020","hex");
const SUITE=Buffer.from("48504b45002000010002","hex");
const INFO=Buffer.from("SPDECODE-V2-HTTP-HPKE-1");
const START=Buffer.from("HPKE-v1");
const EMPTY=Buffer.alloc(0);
export const REQUEST_MAGIC=Buffer.from("SP2Q");
export const RESPONSE_MAGIC=Buffer.from("SP2R");
const hash=b=>createHash("sha256").update(b).digest();
const hmac=(key,data)=>createHmac("sha256",key).update(data).digest();
function extract(salt,ikm){return hmac(salt.length?salt:Buffer.alloc(32),ikm);}
function expand(prk,info,length){
  if(length>255*32||length<0)throw Error("HPKE_LENGTH");
  let previous=EMPTY;const out=[];let size=0;
  for(let n=1;size<length;n++){
    previous=hmac(prk,Buffer.concat([previous,info,Buffer.from([n])]));
    out.push(previous);size+=32;
  }
  return Buffer.concat(out).subarray(0,length);
}
function labelExtract(suite,salt,label,ikm){
  return extract(salt,Buffer.concat([START,suite,Buffer.from(label),ikm]));
}
function labelExpand(suite,prk,label,info,length){
  return expand(prk,Buffer.concat([Buffer.from([length>>8,length&255]),START,suite,Buffer.from(label),info]),length);
}
function receiverContext(rawPrivate,enc){
  if(enc.length!==32)throw Error("HPKE_ENC");
  const sk=createPrivateKey({key:Buffer.concat([P8,rawPrivate]),format:"der",type:"pkcs8"});
  const pk=createPublicKey(sk).export({format:"der",type:"spki"}).subarray(SPKI.length);
  const eph=createPublicKey({key:Buffer.concat([SPKI,enc]),format:"der",type:"spki"});
  const dh=diffieHellman({privateKey:sk,publicKey:eph});
  const eae=labelExtract(KEM,EMPTY,"eae_prk",dh);
  const secret=labelExpand(KEM,eae,"shared_secret",Buffer.concat([enc,pk]),32);
  const pskHash=labelExtract(SUITE,EMPTY,"psk_id_hash",EMPTY);
  const infoHash=labelExtract(SUITE,EMPTY,"info_hash",INFO);
  const context=Buffer.concat([Buffer.from([0]),pskHash,infoHash]);
  const derived=labelExtract(SUITE,secret,"secret",EMPTY);
  return {
    key:labelExpand(SUITE,derived,"key",context,32),
    nonce:labelExpand(SUITE,derived,"base_nonce",context,12),
    exporter:labelExpand(SUITE,derived,"exp",context,32),
  };
}
export function hpkeServerKey(env=process.env){
  const encoded=env.CLOUD_V2_HPKE_PRIVATE_KEY||"";
  if(!/^[A-Za-z0-9_-]{43}$/.test(encoded))throw Error("V2_HPKE_KEY_MISSING");
  const raw=Buffer.from(encoded,"base64url");
  if(raw.length!==32||raw.toString("base64url")!==encoded)throw Error("V2_HPKE_KEY_INVALID");
  const secret=createPrivateKey({key:Buffer.concat([P8,raw]),format:"der",type:"pkcs8"});
  return {privateSeed:raw,publicKey:createPublicKey(secret).export({format:"der",type:"spki"}).subarray(SPKI.length).toString("base64url")};
}
function aad(direction,operation,version,timestamp,nonce,bearer,wire,status){
  const parts=["SPDECODE-V2-HPKE-1",direction,String(operation),version,timestamp,nonce,hash(Buffer.from(bearer)).toString("hex")];
  if(direction==="response")parts.push(hash(wire).toString("hex"),String(status));
  return Buffer.from(parts.join("\n"));
}
function responseSecret(exporter,wire){
  const digest=hash(wire);
  return {key:labelExpand(SUITE,exporter,"sec",Buffer.concat([Buffer.from("SPDECODE-REPLY-KEY"),digest]),32),
    nonce:labelExpand(SUITE,exporter,"sec",Buffer.concat([Buffer.from("SPDECODE-REPLY-NONCE"),digest]),12)};
}
export function openRequest(wire,recipient,meta){
  if(!Buffer.isBuffer(wire)||wire.length<4+32+16||!wire.subarray(0,4).equals(REQUEST_MAGIC))
    throw Error("HPKE_ENVELOPE");
  const ctx=receiverContext(recipient.privateSeed,wire.subarray(4,36));
  const ciphertext=wire.subarray(36,wire.length-16),tag=wire.subarray(wire.length-16);
  const cipher=createDecipheriv("aes-256-gcm",ctx.key,ctx.nonce);
  cipher.setAAD(aad("request",meta.operation,meta.version,meta.timestamp,meta.nonce,meta.bearer));
  cipher.setAuthTag(tag);
  const clear=Buffer.concat([cipher.update(ciphertext),cipher.final()]);
  return {clear,reply:(status,responseBytes)=>{
    const {key,nonce}=responseSecret(ctx.exporter,wire);
    const box=createCipheriv("aes-256-gcm",key,nonce);
    box.setAAD(aad("response",meta.operation,meta.version,meta.timestamp,meta.nonce,meta.bearer,wire,status));
    return Buffer.concat([RESPONSE_MAGIC,box.update(responseBytes),box.final(),box.getAuthTag()]);
  }};
}
export async function encryptedReply(context,status,response){
  const bytes=Buffer.from(await response.arrayBuffer());
  return new Response(context.reply(status,bytes),{status,headers:{"Content-Type":"application/octet-stream","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
}
