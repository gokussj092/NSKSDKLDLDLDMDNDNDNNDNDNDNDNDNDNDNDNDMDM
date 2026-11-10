"use client";
import {createAuthClient} from 'better-auth/react';
import {usePublicLocale} from './site-chrome.jsx';
export const authClient=createAuthClient();
export async function shopFetch(url,body,method='POST'){
  const response=await fetch(url,{method:body===undefined?'GET':method,credentials:'same-origin',cache:'no-store',
    ...(body===undefined?{}:{headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})});
  const data=await response.json();if(!response.ok)throw Error(data.error?.code||'SERVICE_UNAVAILABLE');return data;
}
export const money=(cents,currency,lang='es')=>new Intl.NumberFormat(lang==='es'?'es-MX':'en-US',
  {style:'currency',currency,currencyDisplay:'code'}).format(cents/100);
export function errorMessage(code,lang){
  const es={SIGN_IN_REQUIRED:'Inicia sesión para continuar.',USERNAME_TAKEN:'Ese nombre de usuario ya está ocupado.',
    INVALID_PROFILE:'Usa un nombre válido y un usuario de 3 a 24 letras, números o guion bajo.',
    HANDLE_CHANGE_LIMIT:'Puedes cambiar tu usuario una vez cada siete días.',
    REAUTHENTICATION_REQUIRED:'Vuelve a iniciar sesión con Google para confirmar tu identidad.',
    TAX_NOT_CONFIGURED:'Las compras todavía no están disponibles para este destino.',
    CURRENCY_UNAVAILABLE:'Elige otra moneda o método de pago.',PRICE_CHANGED:'El precio cambió. Revisa el total de nuevo.',
    CHECKOUT_IN_PROGRESS:'Estamos preparando tu pago. Inténtalo de nuevo en unos segundos.',
    PUBLIC_IP_REQUIRED:'Introduce la IP pública de salida de tu servidor.',
    ALREADY_REVEALED:'Esta clave ya se mostró. Las API Keys se pueden renovar desde tu cuenta.',
    PRODUCT_UNAVAILABLE:'Este producto aún no está disponible para comprar.',
    ACCOUNTS_NOT_CONFIGURED:'El acceso a cuentas estará disponible próximamente.'};
  const en={SIGN_IN_REQUIRED:'Sign in to continue.',USERNAME_TAKEN:'That username is already taken.',
    INVALID_PROFILE:'Use a valid name and a username with 3–24 letters, numbers or underscores.',
    HANDLE_CHANGE_LIMIT:'You can change your username once every seven days.',
    REAUTHENTICATION_REQUIRED:'Sign in with Google again to confirm your identity.',
    TAX_NOT_CONFIGURED:'Purchases are not available for this destination yet.',
    CURRENCY_UNAVAILABLE:'Choose another currency or payment method.',PRICE_CHANGED:'The price changed. Review the total again.',
    CHECKOUT_IN_PROGRESS:'Your checkout is being prepared. Please retry in a few seconds.',
    PUBLIC_IP_REQUIRED:'Enter your server’s public outbound IP address.',
    ALREADY_REVEALED:'This key has already been revealed. API keys can be rotated in your account.',
    PRODUCT_UNAVAILABLE:'This product is not available to purchase yet.',
    ACCOUNTS_NOT_CONFIGURED:'Account sign-in is coming soon.'};
  return (lang==='es'?es:en)[code]||(lang==='es'?'No pudimos completar la solicitud. Inténtalo de nuevo.':'We could not complete the request. Please try again.');
}
export function GoogleButton({disabled=false,callback='/account',onError}){
  const {lang}=usePublicLocale();
  return <button className="sp-google-button" disabled={disabled} onClick={async()=>{
    try{const result=await authClient.signIn.social({provider:'google',callbackURL:callback,
      acceptedTerms:'2026-11-10',acceptedPrivacy:'2026-11-10'});
      if(result.error)onError?.(errorMessage(result.error.code,lang));}
    catch{onError?.(errorMessage('SERVICE_UNAVAILABLE',lang));}
  }}><svg width="20" height="20" viewBox="0 0 48 48" aria-hidden="true">
    <path fill="#4285F4" d="M43.6 24.5c0-1.4-.1-2.8-.4-4.1H24v7.8h11a9.4 9.4 0 0 1-4.1 6.2v5h6.6c3.9-3.6 6.1-8.8 6.1-14.9Z"/>
    <path fill="#34A853" d="M24 44c5.5 0 10.1-1.8 13.5-4.9l-6.6-5a12.2 12.2 0 0 1-18.1-6.4H6v5.2A20.4 20.4 0 0 0 24 44Z"/>
    <path fill="#FBBC05" d="M12.8 27.7a12 12 0 0 1 0-7.4V15H6a20 20 0 0 0 0 18l6.8-5.3Z"/>
    <path fill="#EA4335" d="M24 12c3 0 5.7 1 7.8 3l5.8-5.7A19.7 19.7 0 0 0 24 4 20.4 20.4 0 0 0 6 15l6.8 5.3A12 12 0 0 1 24 12Z"/>
   </svg>{lang==='es'?'Continuar con Google':'Continue with Google'}</button>;
}
export function ProductIcon({type}){return <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={type==='offline-3'?'M7 2h10v20H7z M10 18h4 M10 6h4 M10 10h4':type==='api-ip'?'m8 5-6 7 6 7 M16 5l6 7-6 7 M14 3l-4 18':'M6 16a5 5 0 1 1 1-10 6 6 0 0 1 11 2 4 4 0 1 1 0 8H6z'}/></svg>;}
