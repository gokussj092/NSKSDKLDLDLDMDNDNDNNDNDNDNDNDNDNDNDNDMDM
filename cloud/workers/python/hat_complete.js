"use strict";
/** Complete HA Tunnel .hat JSON for the Cloud worker.
 * Historical AES-128-ECB envelope and profilev5 XOR; preserve all nested data.
 * Never log decrypted content, input data or credentials.
 */
const fs=require("node:fs");
const crypto=require("node:crypto");
const KEY=Buffer.from("zbNkuNCGSLivpEuep3BcNA==","base64");
const XOR=String.fromCharCode(42,42,114,86,103,55,69,107,76,126,99,50,96,68,91,97,78,110);
const MAX=12*1024*1024;
function xorField(encoded){
  if(typeof encoded!=="string"||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))
    throw Error("UNSUPPORTED_PROFILEV5_FIELD");
  const raw=Buffer.from(encoded,"base64").toString("utf8");
  let value="";
  for(let i=0;i<raw.length;i++)value+=String.fromCharCode(raw.charCodeAt(i)^XOR.charCodeAt(i%XOR.length));
  return value;
}
function decodeHat(input){
  if(!Buffer.isBuffer(input)||input.length===0||input.length>MAX)throw Error("INVALID_INPUT");
  const encoded=input.toString("utf8").trim();
  if(!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))
    throw Error("INVALID_BASE64");
  const bytes=Buffer.from(encoded,"base64");
  if(bytes.length===0||bytes.length%16!==0)throw Error("INVALID_ENVELOPE");
  const dec=crypto.createDecipheriv("aes-128-ecb",KEY,null);
  const plain=Buffer.concat([dec.update(bytes),dec.final()]);
  const parsed=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(plain));
  if(!parsed||typeof parsed!=="object"||Array.isArray(parsed))throw Error("INVALID_CONFIG");
  if(parsed.profilev5&&typeof parsed.profilev5==="object"&&!Array.isArray(parsed.profilev5)){
    for(const name of ["connection_mode","custom_payload","custom_sni","custom_host"]){
      if(Object.hasOwn(parsed.profilev5,name))parsed.profilev5[name]=xorField(parsed.profilev5[name]);
    }
  }
  return parsed;
}
if(require.main===module){
  try{
    if(process.argv.length!==3)throw Error("USAGE");
    process.stdout.write(JSON.stringify(decodeHat(fs.readFileSync(process.argv[2])),null,2)+"\n");
  }catch(_error){process.exitCode=1;}
}
module.exports={decodeHat};
