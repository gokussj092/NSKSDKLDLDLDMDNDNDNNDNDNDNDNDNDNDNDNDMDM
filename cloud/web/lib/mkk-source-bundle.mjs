/** MKK's four approved downloads may together exceed the 12 MiB worker
 * envelope although individual sources pass the 8 MiB fetch cap.
 * Keep as many complete sources as fit, marking exclusions explicitly; never
 * discard bytes silently or let a single oversized catalog fail the whole job.
 */
// Four fixed MKK catalogs may each use the 8 MiB download cap.
// This Base64 envelope holds them together without dropping any source.
export const MKK_BUNDLE_LIMIT=45*1024*1024;
const KIND="spdecode-mkk-sources-v1";
export const MKK_NAMES=Object.freeze(["servers","static","subscriptions","legacy-subscriptions"]);
export function packMkkSources(items,budget=MKK_BUNDLE_LIMIT){
 if(!Array.isArray(items)||items.length!==MKK_NAMES.length ||
   !Number.isSafeInteger(budget)||budget<128||budget>MKK_BUNDLE_LIMIT ||
   items.some((x,i)=>!x||x.name!==MKK_NAMES[i]||!["ok","error"].includes(x.status)))
  throw Error("INVALID_MKK_SOURCES");
 const compact=items.map(x=>x.status==="ok"?
    {name:x.name,status:"error",error:"REMOTE_TOO_LARGE"}:x);
 for(let i=0;i<items.length;i++){
  if(items[i].status!=="ok")continue;
  const candidate=[...compact];candidate[i]=items[i];
  if(Buffer.byteLength(JSON.stringify({kind:KIND,sources:candidate}),"utf8")<=budget)
    compact[i]=items[i];
 }
 const encoded=Buffer.from(JSON.stringify({kind:KIND,sources:compact}),"utf8");
 if(encoded.length>budget)throw Error("INVALID_MKK_BUNDLE_BUDGET");
 return {payload:encoded,sources:compact};
}
