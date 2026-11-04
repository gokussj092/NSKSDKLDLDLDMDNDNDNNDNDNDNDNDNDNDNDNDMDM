/** Maya Tun PRO maya:// references. Strict, source-pinned, server-only importer.
 * Never embeds a GitHub credential in an APK, file, log or request URL.
 */
import {createDecipheriv} from "node:crypto";
import {downloadApproved,ExternalImportError} from "./c35-provider.mjs";

export const MAYA_GITHUB_HOST="api.github.com";
export const MAYA_GITHUB_PATH="/repos/janatshaban/noob_files/contents/config/mayatun/";
const KEY=Buffer.from(
  "360b82639d6fb4642dc69a1e7b9c720644f9227c7c2f1cc6da14ba9a7dcfead0","hex");
const MAX_REFERENCE=512;
const MAX_FILE=3*1024*1024;
const MAX_RESPONSE=8*1024*1024;
const fail=(code)=>{throw new ExternalImportError(code);};

export function parseMayaReference(value) {
  if(typeof value!=="string" || value.length>MAX_REFERENCE || !value.startsWith("maya://"))
    fail("INVALID_REFERENCE");
  const text=value.slice(7);
  if(!text || text.length%4!==0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(text))
    fail("INVALID_REFERENCE");
  const blob=Buffer.from(text,"base64");
  if(blob.length<29 || blob.length>MAX_REFERENCE ||
     blob.toString("base64")!==text)fail("INVALID_REFERENCE");
  let decoded;
  try{
    const decipher=createDecipheriv("chacha20-poly1305",KEY,blob.subarray(0,12),
      {authTagLength:16});
    decipher.setAuthTag(blob.subarray(-16));
    decoded=Buffer.concat([decipher.update(blob.subarray(12,-16)),decipher.final()]);
  }catch{fail("REMOTE_INTEGRITY_FAILED");}
  let id;
  try{id=new TextDecoder("utf-8",{fatal:true}).decode(decoded);}
  catch{fail("INVALID_REFERENCE");}
  if(!/^[A-Za-z0-9_-]{1,64}$/.test(id))fail("INVALID_REFERENCE");
  return id;
}

export function mayaGithubUrl(id) {
  if(typeof id!=="string" || !/^[A-Za-z0-9_-]{1,64}$/.test(id))
    fail("INVALID_REFERENCE");
  return "https://"+MAYA_GITHUB_HOST+MAYA_GITHUB_PATH+id+".maya";
}

export async function importMayaReference(value,{
  env=process.env,download=downloadApproved,transportOptions={}
}={}) {
  const id=parseMayaReference(value);
  const token=env.CLOUD_MAYA_GITHUB_TOKEN;
  if(token!==undefined && (typeof token!=="string" || !token.trim() ||
      token.includes("\r") || token.includes("\n") || token.length>512))
    fail("REMOTE_NOT_CONFIGURED");
  const url=mayaGithubUrl(id);
  const headers={
    "User-Agent":"SP-DECODE-Maya-Reference/1.0",
    "Accept":"application/vnd.github+json",
    "X-GitHub-Api-Version":"2022-11-28",
    ...(token?{"Authorization":"Bearer "+token.trim()}:{})
  };
  const response=await download({
    url,kind:"maya",method:"GET",headers,maxBytes:MAX_RESPONSE
  },transportOptions);
  if(!Buffer.isBuffer(response) || response.length<2 ||
     response.length>MAX_RESPONSE)fail("REMOTE_RESPONSE_INVALID");
  let metadata;
  try{metadata=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(response));}
  catch{fail("REMOTE_RESPONSE_INVALID");}
  const expected=id+".maya";
  if(!metadata || Array.isArray(metadata) || metadata.type!=="file" ||
      metadata.name!==expected ||
      metadata.path!=="config/mayatun/"+expected ||
      metadata.encoding!=="base64" ||
      typeof metadata.content!=="string" ||
      typeof metadata.size!=="number" ||
      !Number.isSafeInteger(metadata.size) || metadata.size<1 || metadata.size>MAX_FILE)
    fail("REMOTE_RESPONSE_INVALID");
  const compact=metadata.content.replace(/\r?\n/g,"");
  if(!compact || compact.length%4!==0 ||
     !/^[A-Za-z0-9+/]+={0,2}$/.test(compact))fail("REMOTE_RESPONSE_INVALID");
  const body=Buffer.from(compact,"base64");
  if(!body.length || body.length>MAX_FILE || body.length!==metadata.size ||
     body.toString("base64")!==compact)fail("REMOTE_RESPONSE_INVALID");
  // GitHub's first Base64 layer unwraps a .maya ASCII Base64 container.
  // Offline worker performs CBC/PKCS7 and authenticated GCM inner-field decode.
  const encoded=body.toString("ascii").trim();
  if(!encoded || !Buffer.from(encoded,"ascii").equals(Buffer.from(encoded,"utf8")) ||
     encoded.length%4!==0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))
    fail("REMOTE_RESPONSE_INVALID");
  const ciphertext=Buffer.from(encoded,"base64");
  if(ciphertext.length<32 || (ciphertext.length-16)%16!==0 ||
     ciphertext.toString("base64")!==encoded)
    fail("REMOTE_RESPONSE_INVALID");
  return body;
}
