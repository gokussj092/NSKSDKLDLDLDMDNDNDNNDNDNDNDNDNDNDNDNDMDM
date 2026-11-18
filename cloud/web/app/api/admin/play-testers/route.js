import {safe,reply} from '../../../../lib/commerce/config.mjs';
import {requirePanel,can} from '../../../../lib/commerce/staff.mjs';
import {listPlayTesters} from '../../../../lib/commerce/play-testers.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Panel de testers de la prueba cerrada de Google Play: SOLO LECTURA.
// Reading needs support.read. There is deliberately NO POST here: rewards
// (credits / ad-free time) are granted BY HAND by Pedro from the panel;
// this endpoint only counts and shows, it never delivers anything.
export const GET=request=>safe(async()=>{
 const principal=await requirePanel(request);
 if(!can(principal,'support.read'))return reply({error:{code:'FORBIDDEN'}},403);
 return reply(await listPlayTesters());
});
