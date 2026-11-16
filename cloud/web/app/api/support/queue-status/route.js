import {safe,reply} from '../../../../lib/commerce/config.mjs';
import {countPendingSupport} from '../../../../lib/commerce/support.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Public queue signal for Yamada's instant support watcher (hook): only the
// number of threads assigned to Yamada whose latest message is from the
// user. No auth, no session, no user data of any kind — never thread ids,
// account ids or names. Deliberately NOT under /api/v1/* (the V1 gate
// blocks all of /api/v1). The second argument carries {db} only in tests
// (Next passes {params}).
export const GET=async(request,{db}={})=>safe(async()=>
 reply({pending:await countPendingSupport(db?{db}:{})}));
