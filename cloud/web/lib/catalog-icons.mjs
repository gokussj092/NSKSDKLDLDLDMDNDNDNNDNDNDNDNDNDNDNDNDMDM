import {readFileSync,statSync} from "node:fs";
import {join,parse} from "node:path";
import {execFileSync} from "node:child_process";
import {createHash} from "node:crypto";
import {isPng,MAX_ICON_BYTES,MAX_PNG_BYTES} from "./catalog-icon-converter.mjs";

const cache=new Map();
// The web image includes scripts/ alongside package.json; avoid bundler asset URLs.
const converter=join(process.cwd(),"scripts","convert-catalog-icon.mjs");
const extensions=[".png",".webp",".jpg",".jpeg",".avif",".gif"];

export function readCatalogIcon(directory,filename) {
  if(typeof filename!=="string"||!/^[a-z0-9-]+\.(png|webp|jpe?g|avif|gif)$/.test(filename))throw Error("INVALID_ORIGINAL_ICON");
  let bytes;
  // A forgotten conversion may leave only the original vendor WebP/JPEG.
  const stem=parse(filename).name;
  for(const candidate of [filename,...extensions.map(ext=>stem+ext).filter(x=>x!==filename)]){
    const path=join(directory,candidate);
    try{
      if(statSync(path).size>MAX_ICON_BYTES)throw Error("INVALID_ORIGINAL_ICON");
      bytes=readFileSync(path);break;
    }catch(error){if(error.code!=="ENOENT")throw error;}
  }
  if(!bytes?.length||bytes.length>MAX_ICON_BYTES)throw Error("INVALID_ORIGINAL_ICON");
  const sourceHash=createHash("sha256").update(bytes).digest("hex");
  const cached=cache.get(sourceHash);if(cached)return cached;
  const png=isPng(bytes)?bytes:execFileSync(process.execPath,[converter],{
    input:bytes,timeout:10000,maxBuffer:MAX_PNG_BYTES,windowsHide:true,stdio:["pipe","pipe","pipe"],
  });
  if(!isPng(png))throw Error("INVALID_ORIGINAL_ICON");
  const result={bytes:png,mimeType:"image/png",sha256:createHash("sha256").update(png).digest("hex")};
  // Fixed catalog roster only; bound cache even if originals are replaced often.
  if(cache.size>=256)cache.clear();cache.set(sourceHash,result);
  return result;
}
