import {accountNotificationsRequest} from '../../../../lib/commerce/account-notices.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const GET=request=>accountNotificationsRequest(request);
export const POST=request=>accountNotificationsRequest(request);
