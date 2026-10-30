import {v1PolicyStatus} from './v1-protection-policy.mjs';
export function isV1Path(path) {
 for(let n=0;n<3;n++){try{const next=decodeURIComponent(path);if(next===path)break;path=next;}catch{break;}}
 path=path.replaceAll('\\','/').replace(/\/{2,}/g,'/');
 path=new URL(path,'http://local.invalid').pathname.toLowerCase();
 return path==='/api/v1'||path.startsWith('/api/v1/');
}
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
export const v1Failure=(code,status)=>Response.json({error:{code}},{status,headers});
export async function v1Gate(request,{loadPolicy=v1PolicyStatus}={}) {
 if(!isV1Path(new URL(request.url).pathname))return;
 try {if(!(await loadPolicy()).apiEnabled)return v1Failure('V1_API_DISABLED',410);}
 catch {return v1Failure('V1_POLICY_UNAVAILABLE',503);}
}
/** Read-only availability for the Nginx internal auth_request. Never changes policy. */
export async function nginxV1Gate({loadPolicy=v1PolicyStatus}={}) {
 try{return new Response(null,{status:(await loadPolicy()).apiEnabled?204:403,headers});}
 catch{return new Response(null,{status:503,headers});}
}
