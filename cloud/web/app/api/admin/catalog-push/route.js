import {publishRequest,publishStatusRequest} from "../../../../lib/c10-admin-catalog.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export function POST(request){return publishRequest(request);}
export function GET(request){return publishStatusRequest(request);}
