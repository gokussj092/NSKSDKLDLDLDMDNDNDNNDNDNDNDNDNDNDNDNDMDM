import {v1Gate} from './lib/v1-gate.mjs';
import {v2Gate} from './lib/v2-gate.mjs';
export async function proxy(request){
 const blocked=await v1Gate(request);if(blocked)return blocked;
 const v2Blocked=await v2Gate(request);if(v2Blocked)return v2Blocked;
 // Preserve the previous canonical trailing-slash redirect, after the V1 gate.
 const url=new URL(request.url);
 if(url.pathname.length>1&&url.pathname.endsWith('/')){
  url.pathname=url.pathname.slice(0,-1);return Response.redirect(url,308);
 }
}
// Match encoded paths. Only the normalized V1/V2 prefixes require disk policy reads.
export const config={matcher:['/:path*']};
