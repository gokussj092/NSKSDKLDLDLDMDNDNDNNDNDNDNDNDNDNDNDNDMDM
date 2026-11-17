import {safe,reply,requireOrigin,jsonBody,fail} from './config.mjs';
import {requireAccount} from './auth.mjs';
import {configureStreakTimeZone} from './account-streak.mjs';

export const streakTimeZoneRequest=(request,{authenticate=requireAccount,db,today}={})=>safe(async()=>{
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 requireOrigin(request);
 const session=await authenticate(request);
 const input=await jsonBody(request,512);
 // No client dates, offsets, counters, rewards, account ids or "claim" action.
 if(!input||Array.isArray(input)||typeof input!=='object'||
    Object.keys(input).length!==1||typeof input.timeZone!=='string')fail('INVALID_REQUEST');
 return reply({streak:await configureStreakTimeZone(session.user.id,input.timeZone,{db,today})});
});
