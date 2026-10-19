import { enabled, notEnabled, decodeRequest } from "../../../../../lib/c3-gateway.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export function POST(request){return enabled()?decodeRequest(request,"file"):notEnabled();}
