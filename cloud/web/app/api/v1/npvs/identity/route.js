import { npvsIdentityRequest } from "../../../../../lib/c3-gateway.mjs";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export function POST(request) { return npvsIdentityRequest(request); }
