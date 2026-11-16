import {safe,reply,jsonBody,requireOrigin} from '../../../../../lib/commerce/config.mjs';
import {requireAccount} from '../../../../../lib/commerce/auth.mjs';
import {appendChunk} from '../../../../../lib/app-analysis.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// One 2 MB chunk as JSON base64 (same transport as APK-QA, no multipart).
export const POST=request=>safe(async()=>{
 const session=await requireAccount(request);
 requireOrigin(request);
 const body=await jsonBody(request,3*1024*1024);
 return reply(await appendChunk(session.user.id,body));
});
