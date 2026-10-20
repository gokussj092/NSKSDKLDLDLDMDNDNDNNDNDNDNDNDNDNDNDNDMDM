import {RECHECK_SECONDS,catalog} from "../../../../../lib/server-vpn-catalog.mjs";
import {providerOverview} from "../../../../../lib/c12-provider-controls.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
const reply=(body,status=200)=>Response.json(body,{status,headers:{"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
export async function POST(request) {
  let input;
  try {
    if(Number(request.headers.get("content-length")||0)>2048) throw Error("body");
    input=await request.json();
    if(!input || typeof input!=="object" || Array.isArray(input) ||
       Object.keys(input).some(k=>k!=="knownVersion") ||
       (input.knownVersion!==undefined && (!Number.isSafeInteger(input.knownVersion) || input.knownVersion<0))) throw Error("schema");
  }catch {return reply({error:{code:"INVALID_REQUEST"}},400);}
  try {
    const summary=await providerOverview();
    const currentVersion=summary.catalogVersion;
    if(input.knownVersion===currentVersion)
      return reply({apiVersion:"v1",catalogVersion:currentVersion,recheckAfterSeconds:RECHECK_SECONDS,unchanged:true});
    const availability=Object.fromEntries(summary.providers.map(p=>[p.id,p.enabled]));
    return reply({...catalog({availability,version:currentVersion}),unchanged:false});
  }catch{return reply({error:{code:"SERVICE_UNAVAILABLE"}},503);}
}
