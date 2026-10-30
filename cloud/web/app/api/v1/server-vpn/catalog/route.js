import {sealCatalog,validCatalogKey} from "../../../../../lib/catalog-envelope.mjs";
import {RECHECK_SECONDS,catalog} from "../../../../../lib/server-vpn-catalog.mjs";
import {providerOverview} from "../../../../../lib/c12-provider-controls.mjs";
import {negotiatesExport,exportPolicy,projectedCatalogVersion,exportCatalog} from "../../../../../lib/compatible-export-policy.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
const reply=(body,status=200)=>Response.json(body,{status,headers:{"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
export async function POST(request) {
  let input;
  try {
    if(Number(request.headers.get("content-length")||0)>2048) throw Error("body");
    input=await request.json();
    if(!input || typeof input!=="object" || Array.isArray(input) ||
       Object.keys(input).some(k=>k!=="knownVersion" && k!=="catalogKey") ||
       (input.catalogKey!==undefined && !validCatalogKey(input.catalogKey)) ||
       (input.knownVersion!==undefined && (!Number.isSafeInteger(input.knownVersion) || input.knownVersion<0))) throw Error("schema");
  }catch {return reply({error:{code:"INVALID_REQUEST"}},400);}
  try {
    const summary=await providerOverview(process.env,{syncCatalog:true});
    const policy=negotiatesExport(request)?await exportPolicy():null;
    const currentVersion=policy?projectedCatalogVersion(request,summary.catalogVersion,policy):summary.catalogVersion;
    if(input.knownVersion===currentVersion)
      return replyFor({apiVersion:"v1",catalogVersion:currentVersion,recheckAfterSeconds:RECHECK_SECONDS,unchanged:true},input.catalogKey);
    const availability=Object.fromEntries(summary.providers.map(p=>[p.id,p.enabled]));
    const result=catalog({availability,version:currentVersion});
    // Existing APKs reject unknown credential names. Keep their snapshot
    // valid while newer clients explicitly negotiate recipient identities.
    if(request.headers.get("x-spdecode-npv-identities")!=="1")
      result.formats=result.formats.map(entry=>({...entry,
        credentialFields:entry.credentialFields.filter(field=>field!=="recipientKey")}));
    const compatibleExports=policy?exportCatalog(request,policy):null;
    return replyFor({...result,...(compatibleExports?{compatibleExports}:{}),unchanged:false},input.catalogKey);
  }catch{return reply({error:{code:"SERVICE_UNAVAILABLE"}},503);}
}

function replyFor(body,key){return reply(key?sealCatalog(body,key,"catalog"):body);}
