import Link from "next/link";
export const metadata={title:"Términos y condiciones",description:"Condiciones de uso de SP-DECODE Cloud."};
export default function Terms(){
  return <main id="main" className="shell page-wrap prose">
    <span className="section-kicker">Información legal</span>
    <h1 className="page-title">Términos y condiciones de SP-DECODE</h1>
    <p className="page-lead">Versión de documento: 18 de octubre de 2026. Documento de desarrollo sujeto a revisión legal antes de la publicación en Google Play.</p>
    <h2>1. Servicio</h2>
    <p>SP-DECODE es una aplicación Android que envía configuraciones seleccionadas expresamente por la persona usuaria a un servicio remoto para interpretar formatos de configuración de aplicaciones VPN. No proporciona conexiones VPN ni garantiza que un perfil funcione en un proveedor externo.</p>
    <h2>2. Uso autorizado</h2>
    <p>Solo deben procesarse configuraciones propias o aquellas para las que se dispone de permiso. No se permite utilizar SP-DECODE para acceder sin autorización a servicios, cuentas o información de terceros, evadir restricciones de acceso o infringir derechos.</p>
    <h2>3. Datos y descifrado</h2>
    <p>Los archivos pueden contener contraseñas, hosts, tokens y otros datos sensibles. Al solicitar un descifrado, el usuario autoriza la transmisión de ese archivo o texto a la API de SP-DECODE para su procesamiento. Las consultas a proveedores externos se limitan a las integraciones previstas y se documentan en la <Link href="/privacy">política de privacidad</Link>.</p>
    <h2>4. Disponibilidad y limitaciones</h2>
    <p>La compatibilidad varía según versiones y formatos. El servicio puede devolver errores, resultados no compatibles o interrumpirse por mantenimiento o dependencias externas. No se garantiza disponibilidad continua ni compatibilidad con todas las aplicaciones VPN.</p>
    <h2>5. Aplicaciones de terceros</h2>
    <p>Los nombres e iconos de aplicaciones externas identifican los formatos compatibles. No implican patrocinio, afiliación ni autorización del titular de sus marcas. La atribución y el uso de recursos gráficos deben revisarse antes de la distribución comercial.</p>
    <h2>6. Responsabilidades</h2>
    <p>La persona usuaria debe comprobar los resultados y proteger las credenciales exportadas. Estas condiciones no limitan derechos irrenunciables que establezca la legislación aplicable ni eximen de responsabilidades que legalmente no puedan excluirse.</p>
    <h2>7. Cambios y contacto</h2>
    <p>Los cambios sustanciales de estas condiciones requerirán una versión actualizada y un nuevo consentimiento cuando corresponda. Para soporte escribe a <a href="mailto:soporte@spdecode.xyz">soporte@spdecode.xyz</a>.</p>
    <div className="notice">Pendiente para producción: identidad legal y domicilio del responsable, derechos de consumidores, jurisdicción, mecanismos de reclamación y revisión de políticas de proveedores y marcas. No debe describirse este borrador como documento legal definitivo.</div>
  </main>;
}
