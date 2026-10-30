import {v2PolicyStatus} from './v2-availability-policy.mjs';
export function isV2Path(path) {
 for(let i=0;i<3;i++){try{const next=decodeURIComponent(path);if(next===path)break;path=next;}catch{break;}}
 path=path.replaceAll('\\','/').replace(/\/{2,}/g,'/');
 path=new URL(path,'http://local.invalid').pathname.toLowerCase();
 return path==='/api/v2'||path.startsWith('/api/v2/');
}
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
export async function v2Gate(request,{loadPolicy=v2PolicyStatus}={}) {
 if(!isV2Path(new URL(request.url).pathname))return;
 try{
  if(!(await loadPolicy()).enabled)
   return Response.json({error:{code:'V2_API_DISABLED'}},{status:410,headers});
 }catch{
  return Response.json({error:{code:'V2_POLICY_UNAVAILABLE'}},{status:503,headers});
 }
}
