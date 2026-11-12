/** Normalize all vendor raster icons before build/start; retain the originals. */
import {readdir,readFile,writeFile,rename,unlink} from "node:fs/promises";
import {join,parse} from "node:path";
import {convertIconToPng} from "../lib/catalog-icon-converter.mjs";
const directory=join(process.cwd(),"public","server-vpn-icons");
let converted=0;
for(const filename of (await readdir(directory)).sort()){
  if(!/^[a-z0-9-]+\.(png|webp|jpe?g|avif|gif)$/.test(filename))continue;
  const target=join(directory,parse(filename).name+".png");
  // An explicit PNG is authoritative when both formats are checked in.
  if(!filename.endsWith(".png")){
    try{await readFile(target);continue;}catch(error){if(error.code!=="ENOENT")throw error;}
  }
  const original=await readFile(join(directory,filename));
  const png=await convertIconToPng(original);
  if(filename.endsWith(".png")&&png.equals(original))continue;
  const temporary=target+"."+process.pid+".tmp";
  try{await writeFile(temporary,png,{flag:"wx"});await rename(temporary,target);converted++;}
  finally{await unlink(temporary).catch(error=>{if(error.code!=="ENOENT")throw error;});}
}
console.log("Catalog icons ready (PNG); converted: "+converted);
