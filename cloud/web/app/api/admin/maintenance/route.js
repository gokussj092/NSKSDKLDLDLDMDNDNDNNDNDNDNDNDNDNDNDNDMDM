import { maintenanceRequest } from "../../../../lib/c6-admin-api.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export function POST(request){return maintenanceRequest(request);}
