import {opsStore} from '../c6-ops-store.mjs';
// Presencia real del personal de soporte (efímera, en Redis; sin migración).
// Cada actividad del personal en las rutas de soporte (listar, leer, responder,
// asignar, escalar) refresca su clave con TTL 20 min: la revisión de Yamada
// corre cada 15 min + 5 de margen, así que mientras la revisión corra (o el
// panel esté abierto) el agente se ve "En línea". Si la revisión se detiene
// o la sesión expira, la clave caduca sola y el agente pasa a "Sin conexión".
// Un fallo de Redis jamás rompe la bandeja: sin clave = offline.
export const STAFF_PRESENCE_TTL_SECONDS=20*60;
export const staffPresenceKey=staffId=>'spdecode:staff:presence:'+staffId;
async function store(redis){
  if(redis)return redis;
  try{return await opsStore();}catch{return null;}
}
export async function touchStaffPresence(redis,staffId){
  if(typeof staffId!=='string'||!staffId)return false;
  const source=await store(redis);
  if(!source)return false;
  try{
    await source.set(staffPresenceKey(staffId),'1',{EX:STAFF_PRESENCE_TTL_SECONDS});
    return true;
  }catch{return false;}
}
export async function staffPresenceOnline(redis,staffIds){
  const ids=[...new Set((staffIds||[]).filter(id=>typeof id==='string'&&id))];
  const out=new Map(ids.map(id=>[id,false]));
  if(!ids.length)return out;
  const source=await store(redis);
  if(!source)return out;
  const found=await Promise.all(ids.map(async id=>{
    try{return (await source.exists(staffPresenceKey(id)))>0;}catch{return false;}
  }));
  ids.forEach((id,i)=>out.set(id,found[i]));
  return out;
}
