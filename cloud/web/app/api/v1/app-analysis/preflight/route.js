import {safe,reply,requireOrigin} from '../../../../../lib/commerce/config.mjs';
import {requireAccount} from '../../../../../lib/commerce/auth.mjs';
import {preflight} from '../../../../../lib/app-analysis.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Server-authoritative credit/price check. The client enables "Importar
// aplicación" only from this response, never from a local value.
export const POST=request=>safe(async()=>{
 const session=await requireAccount(request);
 requireOrigin(request);
 return reply(await preflight(session.user.id));
});
