import Link from "next/link";
export const metadata={title:"Privacidad",description:"Información sobre tratamiento de archivos y protección de datos en SP-DECODE Cloud."};
export default function Privacy(){
  return <main id="main" className="shell page-wrap prose"><span className="section-kicker">Privacidad</span><h1 className="page-title">Transparencia sobre los archivos y los datos</h1>
  <p className="page-lead">Versión del borrador: 18 de octubre de 2026. Documento informativo provisional de SP-DECODE Cloud que necesita revisión legal antes del lanzamiento público.</p>
  <h2>Qué recibe el servidor</h2><p>Cuando el usuario activa expresamente un descifrado en Android, la API recibe el archivo o texto cifrado. Algunos formatos requieren contraseña o HWID aportados por el usuario. Las importaciones externas consultan proveedores permitidos y podrían transmitir una referencia de configuración a ese proveedor.</p>
  <h2>Cómo se procesa</h2><p>Los datos se envían por HTTPS al servidor y se procesan en workers privados. Se usan límites de tamaño y tiempo y directorios temporales que se eliminan al terminar la operación. La API no incorpora un almacenamiento persistente de los archivos o resultados procesados.</p>
  <h2>Autenticación y prevención de abuso</h2><p>La arquitectura utiliza desafíos temporales de Play Integrity, tokens de sesión de corta duración y Redis para control de solicitudes. Las IP pueden procesarse en forma de identificadores hash para limitar abusos. El panel administrativo solo muestra contadores agregados, nunca el contenido de los archivos.</p>
  <h2>Historial y resultados en Android</h2><p>Los resultados se presentan en la aplicación Android, cuyo historial se guarda localmente según la configuración del dispositivo. El sitio web no ofrece un visor de archivos subidos ni un historial remoto.</p>
  <h2>Estado de la política</h2><p>Antes de publicar la aplicación deberán documentarse la identidad legal del responsable, medios de contacto, jurisdicción, condiciones de proveedores externos, bases de tratamiento, plazo concreto de conservación de metadatos, derechos de los usuarios y procedimientos de eliminación. Esta información no debe darse por definitiva hasta esa revisión.</p>
  <h2>Contacto de soporte</h2><p>Para consultas generales del proyecto puedes escribir a <a href="mailto:soporte@spdecode.xyz">soporte@spdecode.xyz</a>. La atención de solicitudes legales y de datos personales se definirá formalmente en el aviso definitivo.</p>
  <div className="notice">La plataforma se encuentra en desarrollo y no está disponible públicamente. Esta página no sustituye el aviso de privacidad legal definitivo requerido para producción.</div>
  <p><Link className="button subtle" href="/docs">Volver a documentación</Link></p></main>;
}
