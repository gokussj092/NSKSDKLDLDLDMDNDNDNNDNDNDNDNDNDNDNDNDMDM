import test from "node:test";
import assert from "node:assert/strict";
import {createCipheriv} from "node:crypto";
import {approvedUrl,ExternalImportError} from "../lib/c35-provider.mjs";
import {parseMayaReference,mayaGithubUrl,importMayaReference} from "../lib/maya-reference.mjs";

const URI="maya://iMRXyO/sbosPgEPZ71e2EYFpaAA+q6is2Nc/iVbn3v8BmShW3xpjA+KPZ8g=";
const ID="6b1bab923bd64697";
const MAIN_KEY=Buffer.from("360b82639d6fb4642dc69a1e7b9c720644f9227c7c2f1cc6da14ba9a7dcfead0","hex");

function syntheticMayaFile(){
 const iv=Buffer.alloc(16,0x24);
 const plaintext=Buffer.from('MAYA TUN PRO\n{"servers":[{"name":"synthetic"}]}',"utf8");
 const encrypt=createCipheriv("aes-256-cbc",MAIN_KEY,iv);
 return Buffer.from(Buffer.concat([iv,encrypt.update(plaintext),encrypt.final()]).toString("base64"),"ascii");
}
function metadata(body,overrides={}){
 return {type:"file",name:ID+".maya",path:"config/mayatun/"+ID+".maya",encoding:"base64",
   size:body.length,content:body.toString("base64"),...overrides};
}
function mockDownload(data, callback){
 return async (request) => {
   callback?.(request);
   assert.equal(request.kind,"maya");
   assert.equal(request.method,"GET");
   assert.equal(request.url,mayaGithubUrl(ID));
   return Buffer.from(JSON.stringify(data));
 };
}

test("user sample Maya link authenticates to its observed opaque identifier",()=>{
 assert.equal(parseMayaReference(URI),ID);
 assert.equal(mayaGithubUrl(ID),
  "https://api.github.com/repos/janatshaban/noob_files/contents/config/mayatun/"+ID+".maya");
});
test("reject invalid input, altered authentication tag and dangerous file identifiers",()=>{
 for(const value of ["maya://","maya://a","MAYA://"+URI.slice(7),
   "maya://"+URI.slice(7).replace(/.$/,"A"),"maya://../../",URI.slice(0,-2)+"AA"]){
   assert.throws(()=>parseMayaReference(value),ExternalImportError);
 }
 for(const id of ["../secrets","a/b","a.b","%2F",""]){
   assert.throws(()=>mayaGithubUrl(id),ExternalImportError);
 }
});
test("Maya network broker pins GitHub origin, path, TLS and forbids other endpoints",()=>{
 assert.equal(approvedUrl(mayaGithubUrl(ID),"maya").hostname,"api.github.com");
 for(const url of [
   "https://api.github.com/repos/janatshaban/noob_files/contents/config/",
   "https://api.github.com/repos/janatshaban/noob_files/contents/config/mayatun/"+ID+".maya?ref=main",
   "https://api.github.com/repos/other/noob_files/contents/config/mayatun/"+ID+".maya",
   "https://api.github.com/repos/janatshaban/noob_files/contents/config/mayatun/../private.maya",
   "http://api.github.com/repos/janatshaban/noob_files/contents/config/mayatun/"+ID+".maya",
   "https://example.com/repos/janatshaban/noob_files/contents/config/mayatun/"+ID+".maya",
 ]){
   assert.throws(()=>approvedUrl(url,"maya"),ExternalImportError);
 }
});
test("GitHub metadata is authenticated structurally before offline CBC/GCM worker",async()=>{
 const body=syntheticMayaFile();
 let request;
 const result=await importMayaReference(URI,{env:{},
   download:mockDownload(metadata(body),spec=>request=spec)});
 assert.deepEqual(result,body);
 assert.equal(request.headers["Accept"],"application/vnd.github+json");
 assert.equal(request.headers["Authorization"],undefined);
 assert.equal(request.maxBytes,8*1024*1024);
});
test("server-only authorization uses provided environment and never sends token in URL",async()=>{
 const body=syntheticMayaFile();
 let request;
 await importMayaReference(URI,{env:{CLOUD_MAYA_GITHUB_TOKEN:"only-for-unit-test"},
   download:mockDownload(metadata(body),spec=>request=spec)});
 assert.equal(request.headers.Authorization,"Bearer only-for-unit-test");
 assert(!request.url.includes("only-for-unit-test"));
});
test("reject malformed, incomplete, HTML, oversized or mismatched GitHub responses",async()=>{
 const body=syntheticMayaFile();
 for(const altered of [
  {encoding:"utf-8"},
  {type:"dir"},
  {name:"other.maya"},
  {path:"config/other/"+ID+".maya"},
  {size:body.length+1},
  {content:"bad"},
  {content:Buffer.from("<html>blocked</html>").toString("base64"),size:20},
 ]){
  await assert.rejects(()=>importMayaReference(URI,{env:{},
    download:mockDownload(metadata(body,altered))}),ExternalImportError);
 }
 await assert.rejects(()=>importMayaReference(URI,{env:{},
   download:async()=>Buffer.from("<html>not found</html>")}),ExternalImportError);
 await assert.rejects(()=>importMayaReference(URI,{env:{CLOUD_MAYA_GITHUB_TOKEN:"unsafe\nheader"},
   download:mockDownload(metadata(body))}),ExternalImportError);
});
