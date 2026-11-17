import {streakTimeZoneRequest} from '../../../../lib/commerce/streak-route.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const POST=request=>streakTimeZoneRequest(request);
