import {safe,reply} from '../../../../lib/commerce/config.mjs';
import {countQueuedJobs} from '../../../../lib/app-analysis.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Public queue signal for Yamada's instant watcher (hook): only the number
// of app-analysis jobs waiting in QUEUED_FOR_ANALYSIS. No auth, no session,
// no user data of any kind — never job ids, account ids or package names.
// Deliberately NOT under /api/v1/* (the V1 gate blocks all of /api/v1).
// The second argument carries {db} only in tests (Next passes {params}).
export const GET=async(request,{db}={})=>safe(async()=>
 reply({queued:await countQueuedJobs(db?{db}:{})}));
