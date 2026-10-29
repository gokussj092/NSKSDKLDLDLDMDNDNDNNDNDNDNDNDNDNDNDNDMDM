import {verifyPushRequest} from "../../../../../lib/app-notifications.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export const POST=request=>verifyPushRequest(request);
