import Link from "next/link";
export const metadata={title:"Documentación",description:"Arquitectura y limitaciones de SP-DECODE Cloud."};
export default function Docs(){
  return <main id="main" className="shell page-wrap prose"><span className="section-kicker">Documentación</span><h1 className="page-title">Cómo funciona SP-DECODE Cloud</h1>
  <p className="page-lead">Esta guía describe la arquitectura prevista para la aplicación Android. La plataforma no ofrece acceso de descifrado mediante este sitio web.</p>
  <h2>1. Selección y envío</h2><p>La aplicación identifica el formato y envía el contenido cifrado mediante HTTPS a una API protegida. En el futuro, el modo Cloud no realizará descifrado offline ni recurrirá a un motor local cuando el servidor falle.</p>
  <h2>2. Verificación de seguridad</h2><p>El servidor verifica la integridad de la aplicación con Google Play Integrity, crea sesiones temporales y aplica límites a las solicitudes. La verificación real con Play Console es una condición pendiente de publicación.</p>
  <h2>3. Procesamiento aislado</h2><p>La API dirige el contenido a un worker privado. Los motores Python, Node.js o PHP realizan el procesamiento fuera del APK. Las claves de proveedor y credenciales operativas no pertenecen al cliente.</p>
  <h2>4. Resultados</h2><p>La respuesta contiene el texto y, cuando corresponde, el JSON estructurado. El resultado aparece en la interfaz Android existente. Algunos archivos podrían requerir contraseña o HWID.</p>
  <h2>Límites técnicos provisionales</h2><div className="info-table"><div><span>Archivo recibido por API</span><strong>8 MiB</strong></div><div><span>Texto por solicitud</span><strong>250.000 caracteres</strong></div><div><span>Sesión de acceso</span><strong>Hasta 5 minutos</strong></div><div><span>Descarga externa autorizada</span><strong>8 MiB</strong></div></div>
  <h2>Direcciones oficiales previstas</h2>
  <p>Información pública: <a href="https://spdecode.xyz">spdecode.xyz</a>; API exclusiva Android: <code>https://api.spdecode.xyz</code>; administración privada: <code>https://panel.spdecode.xyz</code>. El correo de contacto es <a href="mailto:soporte@spdecode.xyz">soporte@spdecode.xyz</a>. La disponibilidad depende del despliegue y las pruebas pendientes.</p>
  <h2>Lo que todavía no está certificado</h2><p>La compatibilidad real con cada variante de exportador, Play Integrity en dispositivos publicados, desempeño en VPS y continuidad del servicio requieren pruebas adicionales. El sitio no anuncia una fecha de lanzamiento.</p>
  <div className="notice"><strong>Importante:</strong> usa únicamente archivos propios o para los que cuentes con autorización. Los archivos pueden incluir datos sensibles. Consulta las <Link href="/privacy">consideraciones de privacidad</Link>.</div>
  <p><Link className="button primary" href="/status">Consultar estado</Link></p></main>;
}
