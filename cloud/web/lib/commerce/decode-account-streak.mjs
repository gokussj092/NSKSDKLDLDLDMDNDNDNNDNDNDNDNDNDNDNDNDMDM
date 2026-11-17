import {requireAccount} from './auth.mjs';
import {recordDecodeDay} from './account-streak.mjs';

// Account credentials belong only to the encrypted transport envelope. Never
// forward them to a decoder, provider, telemetry, or use a client account ID.
export function takeStreakAccountToken(payload,claims){
 if(!payload||typeof payload!=='object'||Array.isArray(payload))return null;
 const token=payload.accountToken;
 delete payload.accountToken;
 return claims?.hpke===true&&claims.scope==='decode'&&typeof claims.key==='string'&&
  typeof token==='string'&&token.length>=24&&token.length<=1024&&!/\s/.test(token)?token:null;
}
export async function withDecodeStreak(response,claims,token,
 {streakDb,streakToday,streakAuthenticate=requireAccount}={}){
 if(!token||claims?.hpke!==true||claims.scope!=='decode'||!response.ok)return response;
 try{
  const body=await response.clone().json();
  if(body.status!=='success'||typeof body.rawText!=='string'||!body.rawText.trim())return response;
  const session=await streakAuthenticate({headers:new Headers({authorization:'Bearer '+token})});
  if(!session?.user?.id||!session.user.emailVerified)return response;
  const streak=await recordDecodeDay(session.user.id,{db:streakDb,today:streakToday});
  const headers=new Headers(response.headers);headers.delete('content-length');
  return new Response(JSON.stringify({...body,streak}),{status:response.status,headers});
 }catch{return response;} // Session/reward outages never discard a valid decode.
}
