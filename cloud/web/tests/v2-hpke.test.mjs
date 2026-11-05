import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createDecipheriv, generateKeyPairSync, randomBytes } from "node:crypto";
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes256Gcm } from "@hpke/core";
import { openHpkeRequest, unpackHpkeBody, sealHpkeReply } from "../lib/v2-hpke.mjs";

const suite=new CipherSuite({kem:new DhkemX25519HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes256Gcm()});
const info=Buffer.from("SPDECODE-V2-HPKE-TRANSPORT-1","ascii");
const responseExport=Buffer.from("SPDECODE-V2-HPKE-RESPONSE-KEY-NONCE-1","ascii");
const responseAad=Buffer.from("SPDECODE-V2-HPKE-RESPONSE-AAD-1","ascii");

async function encrypt(op,metadata,attachment=Buffer.alloc(0)) {
  const kp=generateKeyPairSync("x25519");
  const pub=kp.publicKey.export({format:"jwk"}).x;
  const priv=kp.privateKey.export({format:"jwk"}).d;
  const raw=Buffer.from(pub,"base64url");
  const kid=createHash("sha256").update(raw).digest().subarray(0,8);
  const recipient=await suite.kem.importKey("raw",raw,true);
  const sender=await suite.createSenderContext({recipientPublicKey:recipient,info});
  const enc=Buffer.from(sender.enc);
  assert.equal(enc.length,32);
  const data=Buffer.from(JSON.stringify(metadata));
  const pt=Buffer.alloc(4+data.length+attachment.length);
  pt.writeUInt32BE(data.length);data.copy(pt,4);attachment.copy(pt,4+data.length);
  const header=Buffer.alloc(71);
  header.write("SPH2",0,"ascii");header[4]=1;header.writeUInt16BE(0x0020,5);
  header.writeUInt16BE(0x0001,7);header.writeUInt16BE(0x0002,9);
  kid.copy(header,11);randomBytes(16).copy(header,19);enc.copy(header,35);
  header.writeUInt32BE(pt.length+16,67);
  const ct=Buffer.from(await sender.seal(pt,Buffer.concat([header,Buffer.from([op])])));
  assert.equal(ct.length,pt.length+16);
  const wire=Buffer.concat([header,ct]);
  const recipientSecret=Buffer.from(await sender.export(responseExport,44));
  return {wire,recipientSecret,kid:kid.toString("hex"),env:{
    CLOUD_V2_HPKE_KEYRING:JSON.stringify([{publicKey:pub,privateKey:priv}])}};
}

test("encrypted file attachment crosses HPKE boundary without Base64 on outer wire",async()=>{
  const file=randomBytes(1024);
  const e=await encrypt(5,{format:"ehi",credentials:{password:"sample-test"}},file);
  const opened=await openHpkeRequest(e.wire,5,e.env);
  const unpacked=JSON.parse(unpackHpkeBody(opened.plaintext,5));
  assert.deepEqual(Buffer.from(unpacked.dataBase64,"base64"),file);
  assert.equal(unpacked.format,"ehi");
  const replyBody=Buffer.from(JSON.stringify({status:"success",rawText:"fixture"}));
  const response=sealHpkeReply(opened,200,replyBody);
  assert.equal(response.toString("ascii",0,4),"SPR2");
  assert.deepEqual(response.subarray(7,23),e.wire.subarray(19,35));
  const decipher=createDecipheriv("aes-256-gcm",e.recipientSecret.subarray(0,32),
    e.recipientSecret.subarray(32,44));
  decipher.setAAD(Buffer.concat([responseAad,createHash("sha256").update(e.wire).digest(),
    response.subarray(0,27)]));
  const cipher=response.subarray(27,-16);
  decipher.setAuthTag(response.subarray(-16));
  assert.deepEqual(Buffer.concat([decipher.update(cipher),decipher.final()]),replyBody);
});

test("tampered ciphertext or substituted operation is rejected",async()=>{
  const e=await encrypt(6,{text:"test"});
  const corrupt=Buffer.from(e.wire);corrupt[corrupt.length-17]^=1;
  await assert.rejects(()=>openHpkeRequest(corrupt,6,e.env));
  await assert.rejects(()=>openHpkeRequest(e.wire,5,e.env));
});

test("invalid key ID and malformed length are rejected",async()=>{
  const e=await encrypt(14,{knownVersion:0,locale:"es"});
  const otherKey=Buffer.from(e.wire);otherKey[11]^=1;
  await assert.rejects(()=>openHpkeRequest(otherKey,14,e.env));
  const badLength=Buffer.from(e.wire);badLength.writeUInt32BE(0,67);
  await assert.rejects(()=>openHpkeRequest(badLength,14,e.env));
});

test("manifest and chunk operations authenticate distinct request bytes and reply contexts",async()=>{
 for(const op of [19,20]){
  const input=op===19?{knownVersion:0}:{snapshotId:"a".repeat(64),manifestHash:"a".repeat(64),objectHash:"b".repeat(64),chunkIndex:1};
  const e=await encrypt(op,input);const opened=await openHpkeRequest(e.wire,op,e.env);
  assert.deepEqual(JSON.parse(unpackHpkeBody(opened.plaintext,op)),input);
  await assert.rejects(()=>openHpkeRequest(e.wire,op===19?20:19,e.env));
  const response=sealHpkeReply(opened,200,Buffer.from(JSON.stringify({snapshotId:input.snapshotId??"c".repeat(64)})));
  assert.deepEqual(response.subarray(7,23),e.wire.subarray(19,35));
 }
});
