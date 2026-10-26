/** Static, audited metadata for Cloud text and online-reference formats.
 * This data NEVER selects a worker/module, remote URL or decoder key.
 * The existing server dispatcher remains the authority for real support.
 */
import {readFileSync,existsSync} from "node:fs";
import {join} from "node:path";

let cache;
export function validatePublicTextFormats(document){
 if(!document || document.schemaVersion!==1 || !Array.isArray(document.formats) ||
    document.formats.length<1 || document.formats.length>256)throw Error("TEXT_FORMATS_INVALID");
 const seen=new Set();
 const formats=[];
 for(const item of document.formats){
  if(!item || Object.keys(item).sort().join(",")!=="kind,name,prefix,suffix" ||
     typeof item.prefix!=="string" || item.prefix.length<4 || item.prefix.length>64 ||
     /^https?:\/\//i.test(item.prefix) ||
     // A protocol declaration is a single audited prefix, never a path.
     // Accept vendor schemes, literal scheme markers and 1FTnl.-style tags,
     // while rejecting traversal such as ../evil or scheme://../secrets.
     !/^(?:[A-Za-z0-9][A-Za-z0-9-]{1,62}:\/\/[A-Za-z0-9/_-]*|[A-Za-z0-9][A-Za-z0-9-]{1,62}:|[A-Za-z0-9][A-Za-z0-9-]{1,62}\.)$/.test(item.prefix) ||
     typeof item.name!=="string" || !item.name.trim() || item.name.length>80 ||
     typeof item.suffix!=="string" || !/^[a-z0-9_-]{1,32}$/.test(item.suffix) ||
     !["text","cloud"].includes(item.kind) ||
     seen.has(item.prefix.toLowerCase()))throw Error("TEXT_FORMATS_INVALID_ENTRY");
  seen.add(item.prefix.toLowerCase());
  formats.push({...item});
 }
 return formats;
}
export function publicTextFormats(){
 if(cache)return cache;
 const deployed=join(process.cwd(),"content","text-formats.json");
 const file=existsSync(deployed)?deployed:new URL("../content/text-formats.json",import.meta.url);
 const raw=readFileSync(file,"utf8");
 if(Buffer.byteLength(raw,"utf8")>32768)throw Error("TEXT_FORMATS_SIZE_LIMIT");
 cache=Object.freeze(validatePublicTextFormats(JSON.parse(raw)));
 return cache;
}

/** Additive capability: old APKs ignore this array and retain textFormats. */
export function publicOnlineReferenceFormats(){
 return ["https://cloudvpn.mrfrankofc.com/","https://link.playsmarty.uk/"].map(prefix=>
  ({prefix,name:"HTTP Custom Cloud",suffix:"hc",kind:"cloud"}));
}
