import {Suspense} from 'react';
import Login from '../public/login.jsx';
export const metadata={title:'Iniciar sesión',robots:{index:false,follow:false}};
export default function Page(){return <Suspense fallback={<main id="main" className="sp-loading">SP-DECODE</main>}><Login/></Suspense>;}
