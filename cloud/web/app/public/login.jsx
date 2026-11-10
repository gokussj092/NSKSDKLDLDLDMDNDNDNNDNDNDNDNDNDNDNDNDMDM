"use client";
import Link from 'next/link';
import {useEffect,useState} from 'react';
import {useSearchParams,useRouter} from 'next/navigation';
import {usePublicLocale,usePublicSession} from './site-chrome.jsx';
import {GoogleButton} from './shop-common.jsx';
const allowed=new Set(['/account','/store','/orders','/receipts','/products']);
export default function LoginPage(){
 const {lang}=usePublicLocale(),{account}=usePublicSession(),router=useRouter(),params=useSearchParams();
 const next=allowed.has(params.get('next'))?params.get('next'):'/account';
 const [enabled,setEnabled]=useState(null),[error,setError]=useState('');
 useEffect(()=>{if(account)router.replace(next);},[account,next,router]);
 useEffect(()=>{let alive=true;fetch('/api/account',{credentials:'same-origin',cache:'no-store'}).then(r=>r.json()).then(d=>{if(alive)setEnabled(d.authEnabled===true);}).catch(()=>{if(alive)setError(lang==='es'?'No se pudo comprobar el acceso.':'Could not check sign-in availability.');});return()=>{alive=false;};},[lang]);
 const es=lang==='es';
 return <main id="main" className="sp-login-page"><div className="sp-login-shell">
  <div className="sp-login-intro"><span className="sp-kicker">SP-DECODE · {es?'TU ESPACIO':'YOUR SPACE'}</span><h1>{es?'Todo lo tuyo, en un solo lugar.':'Your space, on your terms.'}</h1><p>{es?'Accede a tu perfil, recibos, licencias y pedidos desde un panel privado. La aplicación Online continúa siendo gratuita, sin necesidad de iniciar sesión.':'Access your profile, receipts, licenses and orders in one private space. The free Online app does not require an account.'}</p><div className="sp-login-points"><span>{es?'Una cuenta · Todas tus compras':'One account · All purchases'}</span><span>{es?'Acceso protegido con Google':'Secure Google sign-in'}</span><span>{es?'Control de tus productos':'Manage your products'}</span></div></div>
  <section className="sp-login-panel" aria-labelledby="sp-login-title"><div className="sp-login-mark"><img src="/icon.svg" alt="" width="54" height="54"/></div><span className="sp-kicker">{es?'ACCESO SEGURO':'SECURE SIGN-IN'}</span><h2 id="sp-login-title">{es?'Bienvenido a SP-DECODE':'Welcome to SP-DECODE'}</h2><p>{es?'Inicia sesión con tu cuenta de Google para continuar.':'Continue with your Google account.'}</p><div className="sp-login-provider"><GoogleButton disabled={enabled!==true} callback={next} onError={setError}/></div>{enabled===false&&<small>{es?'El inicio de sesión está temporalmente deshabilitado.':'Sign-in is currently unavailable.'}</small>}{error&&<p role="alert" className="sp-form-error">{error}</p>}<p className="sp-login-terms">{es?'Al continuar, aceptas los':'By continuing you accept the'} <Link href="/terms">{es?'términos':'terms'}</Link> {es?'y la':'and the'} <Link href="/privacy">{es?'política de privacidad':'privacy policy'}</Link>.</p><div className="sp-login-back"><Link href="/">{es?'Volver al inicio':'Back home'}</Link><Link href="/store">{es?'Explorar tienda':'Explore store'}</Link></div></section>
 </div></main>;
}
