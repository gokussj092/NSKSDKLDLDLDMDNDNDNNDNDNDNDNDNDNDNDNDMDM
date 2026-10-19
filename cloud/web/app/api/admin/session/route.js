import { statusRequest } from "../../../../lib/c6-admin-api.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export function GET(request){return statusRequest(request);}
