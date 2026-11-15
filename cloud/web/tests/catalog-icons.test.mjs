import test from "node:test";
import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {mkdtempSync,writeFileSync,rmSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {createHash} from "node:crypto";
import {execFileSync} from "node:child_process";
import {readCatalogIcon} from "../lib/catalog-icons.mjs";
import {convertIconToPng,isPng} from "../lib/catalog-icon-converter.mjs";
const sharp=createRequire(import.meta.url)("sharp");
const raster=()=>sharp({create:{width:12,height:10,channels:4,background:{r:40,g:120,b:220,alpha:1}}});
const temporary=t=>{const dir=mkdtempSync(join(tmpdir(),"catalog-icons-"));t.after(()=>rmSync(dir,{recursive:true,force:true}));return dir;};

test("runtime converts missing-PNG WebP and mislabeled JPEG; digests match actual PNG",async t=>{
 const dir=temporary(t);
 for(const [file,bytes] of [["vendor.webp",await raster().webp({lossless:true}).toBuffer()],["mislabeled.png",await raster().jpeg().toBuffer()]]){
  writeFileSync(join(dir,file),bytes);const result=readCatalogIcon(dir,file==="vendor.webp"?"vendor.png":file);
  assert(isPng(result.bytes));assert.equal(result.mimeType,"image/png");
  assert.equal(result.sha256,createHash("sha256").update(result.bytes).digest("hex"));
  const pixels=await sharp(bytes).ensureAlpha().raw().toBuffer();
  assert.deepEqual(await sharp(result.bytes).ensureAlpha().raw().toBuffer(),pixels);
 }
});
test("valid originals retain exact hashes; replaced input invalidates conversion cache",async t=>{
 const dir=temporary(t),original=await raster().png().toBuffer();writeFileSync(join(dir,"vendor.png"),original);
 assert.deepEqual(readCatalogIcon(dir,"vendor.png").bytes,original);
 writeFileSync(join(dir,"vendor.png"),await raster().negate().webp({lossless:true}).toBuffer());
 assert.notEqual(readCatalogIcon(dir,"vendor.png").sha256,createHash("sha256").update(original).digest("hex"));
});
test("invalid images, vectors, oversize input and untrusted paths fail safely",async t=>{
 const dir=temporary(t);writeFileSync(join(dir,"bad.webp"),"<html>Site Unavailable</html>");
 assert.throws(()=>readCatalogIcon(dir,"bad.png"));assert.throws(()=>readCatalogIcon(dir,"../secret.png"));
 await assert.rejects(()=>convertIconToPng(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>')));
 await assert.rejects(()=>convertIconToPng(Buffer.alloc(2*1024*1024+1)));
});
test("startup preparation automatically creates PNG and is idempotent",async t=>{
 const root=temporary(t);const {mkdirSync,readFileSync}=await import("node:fs");
 const dir=join(root,"public/server-vpn-icons");mkdirSync(dir,{recursive:true});
 const source=await raster().webp({lossless:true}).toBuffer();writeFileSync(join(dir,"vendor.webp"),source);
 const script=new URL("../scripts/prepare-catalog-icons.mjs",import.meta.url);
 execFileSync(process.execPath,[script.pathname],{cwd:root});const png=readFileSync(join(dir,"vendor.png"));
 assert(isPng(png));assert.deepEqual(readFileSync(join(dir,"vendor.webp")),source);
 execFileSync(process.execPath,[script.pathname],{cwd:root});assert.deepEqual(readFileSync(join(dir,"vendor.png")),png);
});
