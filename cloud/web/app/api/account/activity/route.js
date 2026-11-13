import {activityRequest} from '../../../../lib/commerce/account-activity.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const GET=request=>activityRequest(request);
