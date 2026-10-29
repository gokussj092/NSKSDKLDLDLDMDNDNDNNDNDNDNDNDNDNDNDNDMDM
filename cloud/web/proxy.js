import {v1Gate} from './lib/v1-gate.mjs';
export async function proxy(request){
 const blocked=await v1Gate(request);if(blocked)return blocked;
 // Preserve the previous canonical trailing-slash redirect, after the V1 gate.
 const url=new URL(request.url);
 if(url.pathname.length>1&&url.pathname.endsWith('/')){
  url.pathname=url.pathname.slice(0,-1);return Response.redirect(url,308);
 }
}
// Match encoded prefixes too. The guard reads storage only for normalized V1 paths.
export const config={matcher:['/:path*']};
