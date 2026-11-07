/**
 * SP-DECODE V2 application transport, draft 1. RFC 9180 base mode:
 * DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM.
 *
 * The authenticated ECDSA request proof, attestation and session admission
 * remain in v2-transport. HPKE base mode is not client authentication.
 * Zero plaintext, private keys or auth tokens are deliberately logged.
 */
import { createHash, createPrivateKey, createPublicKey, createCipheriv, randomBytes } from "node:crypto";
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from "@hpke/core";

export const HPKE_HEADER_BYTES=71;
export const HPKE_REPLY_HEADER_BYTES=27;
export const HPKE_MAX_BYTES=11*1024*1024;
const INFO=Buffer.from("SPDECODE-V2-HPKE-TRANSPORT-1","ascii");
const EXPORT=Buffer.from("SPDECODE-V2-HPKE-RESPONSE-KEY-NONCE-1","ascii");
const RESPONSE_AAD=Buffer.from("SPDECODE-V2-HPKE-RESPONSE-AAD-1","ascii");
const suite=new CipherSuite({kem:new DhkemX25519HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes256Gcm()});
const digest=bytes=>createHash("sha256").update(bytes).digest();
const keyId=pub=>digest(pub).subarray(0,8).toString("hex");
const b64=raw=>Buffer.from(raw,"base64url");
const canonical=raw=>typeof raw==="string"&&/^[A-Za-z0-9_-]{43}$/.test(raw)&&b64(raw).toString("base64url")===raw;
let cacheText,cacheKeys;

function activeKeys(env=process.env) {
  const text=env.CLOUD_V2_HPKE_KEYRING||"";
  if(!text)throw Error("HPKE_UNCONFIGURED");
  if(text===cacheText && cacheKeys)return cacheKeys;
  // Format: JSON array of {publicKey,privateKey} using 32-byte base64url raw keys.
  // Key IDs are automatically derived (SHA-256(publicKey)[0..8]).
  const entries=JSON.parse(text);
  if(!Array.isArray(entries)||entries.length<1||entries.length>3)throw Error("HPKE_KEYRING_INVALID");
  const keys=new Map();
  for(const entry of entries){
    if(!canonical(entry.publicKey)||!canonical(entry.privateKey))throw Error("HPKE_KEYRING_INVALID");
    const publicRaw=b64(entry.publicKey),kid=keyId(publicRaw);
    const privateJwk={kty:"OKP",crv:"X25519",d:entry.privateKey,x:entry.publicKey};
    const privateKey=createPrivateKey({key:privateJwk,format:"jwk"});
    const check=createPublicKey(privateKey).export({format:"jwk"});
    if(check.x!==entry.publicKey||keys.has(kid))throw Error("HPKE_KEYRING_INVALID");
    keys.set(kid,{jwk:privateJwk});
  }
  cacheText=text;cacheKeys=keys;
  return keys;
}
function cleanHeader(raw,op) {
  if(!Buffer.isBuffer(raw)||raw.length<HPKE_HEADER_BYTES+16||raw.length>HPKE_MAX_BYTES||
     !Number.isInteger(op)||op<1||op>24||op===3||
     raw.toString("ascii",0,4)!=="SPH2"||raw[4]!==1||
     raw.readUInt16BE(5)!==0x20||raw.readUInt16BE(7)!==1||raw.readUInt16BE(9)!==2||
     raw.readUInt32BE(67)!==raw.length-HPKE_HEADER_BYTES)throw Error("HPKE_INVALID");
  return {header:raw.subarray(0,HPKE_HEADER_BYTES),
    keyId:raw.subarray(11,19).toString("hex"),
    messageId:raw.subarray(19,35),
    enc:raw.subarray(35,67), ciphertext:raw.subarray(HPKE_HEADER_BYTES)};
}
export async function openHpkeRequest(raw,op,env=process.env) {
  const parsed=cleanHeader(raw,op);
  const key=activeKeys(env).get(parsed.keyId);
  if(!key)throw Error("HPKE_UNKNOWN_KEY");
  const privateKey=await suite.kem.importKey("jwk",key.jwk,false);
  const context=await suite.createRecipientContext({
    recipientKey:privateKey,enc:parsed.enc,info:INFO,
  });
  const aad=Buffer.concat([parsed.header,Buffer.from([op])]);
  const plaintext=Buffer.from(await context.open(parsed.ciphertext,aad));
  if(plaintext.length<4||plaintext.length>HPKE_MAX_BYTES)throw Error("HPKE_INVALID");
  const responseMaterial=Buffer.from(await context.export(EXPORT,44));
  return {plaintext, responseMaterial, messageId:parsed.messageId,
    replayId:parsed.keyId+":"+parsed.messageId.toString("hex"),
    requestHash:digest(raw),keyId:parsed.keyId};
}
/** Simple binary payload: u32be JSON metadata length | UTF-8 JSON | raw file bytes.
 * Only op=5 or op=22 may carry the binary tail. V1 worker receives its existing Base64
 * body internally; Base64 is not sent on the Android-VPS wire.
 */
export function unpackHpkeBody(plaintext,op) {
  if(plaintext.length<6)throw Error("HPKE_INVALID");
  const size=plaintext.readUInt32BE(0);
  if(size<2||size>1024*1024||size>plaintext.length-4)throw Error("HPKE_INVALID");
  const text=new TextDecoder("utf-8",{fatal:true}).decode(plaintext.subarray(4,4+size));
  const payload=JSON.parse(text);
  if(!payload||typeof payload!=="object"||Array.isArray(payload))throw Error("HPKE_INVALID");
  const tail=plaintext.subarray(4+size);
  if(op===5 || op===22) {
    if(tail.length<1||tail.length>(op===22?2*1024*1024:8*1024*1024)||
       Object.prototype.hasOwnProperty.call(payload,"dataBase64"))throw Error("HPKE_INVALID");
    payload.dataBase64=tail.toString("base64");
  } else if(tail.length!==0)throw Error("HPKE_INVALID");
  return Buffer.from(JSON.stringify(payload),"utf8");
}
export function sealHpkeReply(opened,status,body) {
  if(!Number.isInteger(status)||status<100||status>599||body.length>96*1024*1024)
    throw Error("HPKE_REPLY_INVALID");
  const header=Buffer.alloc(HPKE_REPLY_HEADER_BYTES);
  header.write("SPR2",0,"ascii");header[4]=1;header.writeUInt16BE(status,5);
  opened.messageId.copy(header,7);
  header.writeUInt32BE(body.length+16,23);
  const key=opened.responseMaterial.subarray(0,32),nonce=opened.responseMaterial.subarray(32,44);
  try {
    const cipher=createCipheriv("aes-256-gcm",key,nonce);
    cipher.setAAD(Buffer.concat([RESPONSE_AAD,opened.requestHash,header]));
    const encrypted=Buffer.concat([cipher.update(body),cipher.final(),cipher.getAuthTag()]);
    return Buffer.concat([header,encrypted]);
  }finally{opened.responseMaterial.fill(0);opened.plaintext.fill(0);}
}
export function isHpkeEnabled(env=process.env) {return env.CLOUD_V2_HPKE_ENABLED==="true";}
export function requiresHpke(env=process.env) {return env.CLOUD_V2_HPKE_ONLY==="true";}
export function hpkeKeyIds(env=process.env) {return [...activeKeys(env).keys()];}
