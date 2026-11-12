import {betterAuth} from "better-auth";
import {bearer} from "better-auth/plugins";
import {randomUUID} from "node:crypto";
import {database} from "./db.mjs";
import {authReady,siteOrigin,fail} from "./config.mjs";
import {normalizeDisplayName} from "../f7-account-identity.mjs";
let instance;
export function makeAuth(db,env=process.env){
  return betterAuth({appName:'SP-DECODE',baseURL:siteOrigin(env),secret:env.BETTER_AUTH_SECRET,
    database:db, trustedOrigins:[siteOrigin(env)],
    emailAndPassword:{enabled:false},
    plugins:[bearer()],
    socialProviders:{google:{clientId:env.GOOGLE_CLIENT_ID,clientSecret:env.GOOGLE_CLIENT_SECRET,prompt:'select_account'}},
    user:{modelName:'shop_user',deleteUser:{enabled:true},changeEmail:{enabled:false},additionalFields:{
      privacyVersion:{type:'string',required:false,input:false},termsVersion:{type:'string',required:false,input:false}}},
    session:{modelName:'shop_session',expiresIn:7*86400,updateAge:86400,freshAge:900},
    account:{modelName:'shop_identity',accountLinking:{enabled:false},encryptOAuthTokens:true,storeStateStrategy:'database'},
    verification:{modelName:'shop_verification'},
    rateLimit:{enabled:true,storage:'database',modelName:'shop_rate_limit',window:60,max:60},
    advanced:{cookiePrefix:'spdecode-account',useSecureCookies:env.NODE_ENV==='production',
      database:{generateId:()=>randomUUID()},defaultCookieAttributes:{httpOnly:true,sameSite:'lax',path:'/'}},
    databaseHooks:{user:{create:{before:async user=>{
      if(!user.emailVerified)throw Error('GOOGLE_EMAIL_NOT_VERIFIED');
      return {data:{...user,name:normalizeDisplayName(user.name)||'SP-DECODE',privacyVersion:'2026-11-10',termsVersion:'2026-11-10'}};
    }},update:{before:async user=>{
      if(user.name!==undefined&&!normalizeDisplayName(user.name))throw Error('INVALID_DISPLAY_NAME');
      return {data:user.name===undefined?user:{...user,name:normalizeDisplayName(user.name)}};
    }},delete:{after:async user=>{
      await db.query("UPDATE spdecode_shop.entitlements SET status='revoked',token_digest=NULL,token_prefix=NULL,allowed_ip=NULL WHERE account_id=$1",[user.id]);
      await db.query("UPDATE spdecode_shop.orders SET allowed_ip=NULL,request_digest='account-deleted' WHERE account_id=$1",[user.id]);
      await db.query('DELETE FROM spdecode_shop.reserved_handles WHERE account_id=$1',[user.id]);
    }}}},logger:{level:'error',log:()=>{}}});
}
export function accountAuth(){
  if(!authReady())fail('ACCOUNTS_NOT_CONFIGURED',503);
  return instance??=makeAuth(database());
}
export async function requireAccount(request,{fresh=false,auth=accountAuth()}={}){
  const session=await auth.api.getSession({headers:request.headers});
  if(!session?.user?.emailVerified)fail('SIGN_IN_REQUIRED',401);
  if(fresh&&Date.now()-new Date(session.session.createdAt).getTime()>900000)fail('REAUTHENTICATION_REQUIRED',401);
  return session;
}
