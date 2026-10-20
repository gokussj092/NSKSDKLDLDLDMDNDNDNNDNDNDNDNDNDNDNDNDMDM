import {adminSettings,authenticateAdmin} from "./c6-admin-auth.mjs";
import {opsStore} from "./c6-ops-store.mjs";
import {readIncidents,installationStats} from "./c9-diagnostics.mjs";
export async function adminDiagnosticsRequest(request,{storeProvider=opsStore}={}){
 if(!adminSettings().enabled)return Response.json({status:"error",error:{code:"ADMIN_DISABLED"}},{status:503});
 try{
  const redis=await storeProvider();
  if(!await authenticateAdmin(redis,request))return Response.json({status:"error",error:{code:"UNAUTHORIZED"}},{status:401});
  const url=new URL(request.url);
  const keys=[...url.searchParams.keys()];
  if(keys.some(k=>k!=="days")||keys.length>1||!["1","7"].includes(url.searchParams.get("days")||"7"))
   return Response.json({status:"error",error:{code:"INVALID_REQUEST"}},{status:400});
  const days=Number(url.searchParams.get("days")||"7");
  const [incidents,installations]=await Promise.all([readIncidents(redis,days),installationStats(redis)]);
  return Response.json({status:"ok",incidents,installations,retentionDays:8},{headers:{"Cache-Control":"private, no-store"}});
 }catch{return Response.json({status:"error",error:{code:"SERVICE_UNAVAILABLE"}},{status:503});}
}
