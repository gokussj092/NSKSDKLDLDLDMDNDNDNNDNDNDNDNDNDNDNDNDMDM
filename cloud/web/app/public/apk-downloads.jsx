"use client";
import {useEffect,useState} from 'react';
import {usePublicLocale} from './site-chrome.jsx';
export default function ApkDownloads(){
 const {lang}=usePublicLocale(),es=lang==='es';
 const [releases,setReleases]=useState({online:null,offline:null});
 useEffect(()=>{let active=true;Promise.all(['online','offline'].map(async channel=>{
  try{const res=await fetch('/api/downloads/'+channel+'?metadata',{cache:'no-store'});if(!res.ok)return [channel,null];const data=await res.json();return [channel,data.available?data:null];}
  catch{return [channel,null];}
 })).then(items=>{if(active)setReleases(Object.fromEntries(items));});return()=>{active=false;};},[]);
 return <section className="sp-section sp-container" id="downloads" aria-label={es?'Descargar aplicación':'Download application'}>
  <div className="sp-section-heading"><span className="sp-kicker">ANDROID · APK</span><h2>{es?'Descarga SP-DECODE':'Download SP-DECODE'}</h2><p>{es?'Elige la edición que necesitas. Solo publicamos archivos APK firmados y verificados.':'Choose the edition you need. Only verified signed APKs are published.'}</p></div>
  <div className="sp-downloads-section">{['online','offline'].map(channel=>{
   const data=releases[channel];return <article key={channel}>
    <img src="/icon.svg" alt="" width="48" height="48"/><h3>SP-DECODE {channel==='online'?'Online':'Offline'}</h3>
    <p>{channel==='online'?(es?'Funciones gratuitas y catálogos compatibles, con conexión al servidor.':'Free features and compatible catalogs with server connectivity.'):(es?'Procesamiento local de los formatos compatibles. La activación de licencia se gestiona por separado.':'Local processing of supported formats. License activation is managed separately.')}</p>
    {data?<a href={'/api/downloads/'+channel}>{es?'Descargar APK':'Download APK'} · v{data.version}</a>:<span className="sp-download-unready">{es?'Pendiente de publicación':'Not yet published'}</span>}
    <small>{data?('SHA-256 '+data.sha256.slice(0,16)+'… · '+(data.bytes/1048576).toFixed(1)+' MiB'):(es?'No hay una versión pública aprobada en el servidor.':'No approved public release on the server.')}</small>
   </article>;
  })}</div>
 </section>;
}
