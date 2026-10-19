import Link from "next/link";
export const metadata={title:"Funciones",description:"Funciones y límites previstos de SP-DECODE Cloud para Android."};
const items=[
  ["Archivos de configuración","Rutas de archivos registradas y seleccionadas por extensión. La compatibilidad de cada versión de exportador requiere pruebas."],
  ["Protocolos de texto","El texto se envía por HTTPS y su procesamiento ocurre en los motores del backend, sin secretos incorporados al cliente."],
  ["HTTP Custom protegido","La contraseña y el HWID se reciben solo para la petición correspondiente; se procesa en el worker y no se almacenan en el historial del servidor."],
  ["HTTP Injector Cloud","Importación desde un proveedor permitido. No se aceptan URLs arbitrarias y se requiere una acción explícita del usuario."],
  ["Catálogos NUR Tunnel","Obtención desde el origen configurado y verificación del sobre cifrado en un motor privado separado."],
  ["Historial en el dispositivo","El resultado se presenta en la app existente. El historial personal se administra localmente por la aplicación Android."],
];
export default function Features(){
  return <main id="main" className="shell page-wrap"><span className="section-kicker">Capacidades</span><h1 className="page-title">Una API. Múltiples motores.</h1>
  <p className="page-lead">SP-DECODE Cloud separa el cliente Android del procesamiento de configuraciones cifradas. Cada ruta necesita validación antes de su disponibilidad pública.</p>
  <div className="feature-grid two">{items.map(([name,body],i)=><article className="feature-card" key={name}>
    <div className="feature-index">{String(i+1).padStart(2,"0")}</div><h2>{name}</h2><p>{body}</p></article>)}</div>
  <div className="notice"><strong>Disponibilidad:</strong> el backend continúa en fase de desarrollo. Las 240 rutas catalogadas no representan certificación de todos los archivos o exportadores.</div>
  <Link className="button primary" href="/docs">Leer la documentación ↗</Link></main>;
}
