import {v1Gate} from './lib/v1-gate.mjs';
export async function proxy(request){return v1Gate(request);}
// Match encoded prefixes too. The guard reads storage only for normalized V1 paths.
export const config={matcher:['/:path*']};
