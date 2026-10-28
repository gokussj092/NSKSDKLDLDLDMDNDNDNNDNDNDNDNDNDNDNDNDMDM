import {adminNotices} from '../../../../lib/app-notifications.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const GET=request=>adminNotices(request);
export const POST=request=>adminNotices(request);
