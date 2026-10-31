// Interoperability: native C++ encrypts, existing server Node HPKE opens.
// Server Node encrypts reply; native C++ authenticates and opens it.
import assert from "node:assert/strict";
import {spawn} from "node:child_process";
import {generateKeyPairSync,createHash} from "node:crypto";
import {openHpkeRequest,sealHpkeReply} from "../cloud/web/lib/v2-hpke.mjs";

const cli=process.argv[2];
assert.ok(cli,"Native CLI path missing");
const pair=generateKeyPairSync("x25519");
const publicKey=pair.publicKey.export({format:"jwk"}).x;
const privateKey=pair.privateKey.export({format:"jwk"}).d;
const recipient=Buffer.from(publicKey,"base64url");
const kid=createHash("sha256").update(recipient).digest().subarray(0,8);
const pin=Buffer.concat([kid,recipient]).toString("hex");
const json=JSON.stringify({text:"México native HPKE v1",category:"test"});
const child=spawn(cli,[pin,json],{stdio:["pipe","pipe","pipe"]});
let lineBuffer="",stderr="",step=0;
child.stderr.setEncoding("utf8");
child.stderr.on("data",d=>stderr+=d);
child.stdout.setEncoding("utf8");
let chain=Promise.resolve();
child.stdout.on("data",chunk=>{
    lineBuffer+=chunk;
    while(lineBuffer.includes("\n")){
        const cut=lineBuffer.indexOf("\n");
        const line=lineBuffer.slice(0,cut).trim();
        lineBuffer=lineBuffer.slice(cut+1);
        chain=chain.then(async()=>{
            if(step++===0){
                const wire=Buffer.from(line,"hex");
                const opened=await openHpkeRequest(wire,6,{
                    CLOUD_V2_HPKE_KEYRING:JSON.stringify([{publicKey,privateKey}])
                });
                const size=opened.plaintext.readUInt32BE(0);
                assert.equal(opened.plaintext.subarray(4,4+size).toString("utf8"),json);
                const reply=sealHpkeReply(opened,200,Buffer.from('{"ok":true}'));
                child.stdin.end(reply.toString("hex")+"\n");
            }else{
                assert.equal(line,'{"ok":true}');
            }
        }).catch(e=>{console.error(e);child.kill();process.exitCode=1;});
    }
});
const exit=await new Promise(resolve=>child.on("close",resolve));
await chain;
assert.equal(exit,0,stderr);
assert.equal(step,2,"Expected request and response validation");
console.log("PASS native C++ RFC9180 HPKE <-> Node server cryptographic roundtrip");
