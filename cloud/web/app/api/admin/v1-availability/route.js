import {v1AvailabilityRequest} from "../../../../lib/c6-admin-api.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export const POST=request=>v1AvailabilityRequest(request);
