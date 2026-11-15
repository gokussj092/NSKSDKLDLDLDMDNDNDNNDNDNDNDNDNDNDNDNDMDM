import {sealCatalog,validCatalogKey} from "../../../../../lib/catalog-envelope.mjs";
import {RECHECK_SECONDS,catalog,iconFor} from "../../../../../lib/server-vpn-catalog.mjs";
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
    const methodStates=Object.fromEntries((summary.methodStatuses||[])
      .map(({id,methodRevision,maintenance})=>[id,{methodRevision,maintenance}]));
    const result=catalog({availability,methodStates,version:currentVersion});
    if(summary.displayVersion!==null)result.displayVersion=summary.displayVersion;
    if(request.headers.get("x-spdecode-catalog-bundle")==="1"){
      const icons=result.apps.map(app=>{
        const icon=iconFor(app.id);
        return {id:app.id,sha256:icon.sha256,mimeType:"image/png",contentBase64:icon.bytes.toString("base64")};
      });
      result.iconBundle={version:1,count:icons.length,icons};
    }
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
