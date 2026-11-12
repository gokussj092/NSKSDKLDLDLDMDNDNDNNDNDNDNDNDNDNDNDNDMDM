# OpenTunnel1.1.1 / build61

Muestra pública del paquete solicitado com.opentunnel.app. Hashes de XAPK/base, certificado extraído, clases e icono original se conservan en generated/identity.json e inspection.json. Se usó JADX completo1.5.6: exit3,24 errores globales; no se declara descompilación completa ni ejecución de la APK.

## Archivos .tnl

Observado: ConfigExportFileActivity llama pf.j. Este serializa Java Properties XML con CONFIG_MODE3. pf.a envuelve el sobre de wd1: PBKDF2-HMAC-SHA256,100000 iteraciones, clave256bits, salt32, nonceGCM12 y tag16; sin AAD. k30/ji confirman SHA256. Se recuperó estáticamente ClientSecrets.getSecret(10) desde JNI_OnLoad0x21e08: ADR0x21e68 apunta0x15864, XOR0xaa durante64bytes, map key10. Solo se publica su hash en native-proof; el formato usa la misma constante pública ya presente en tnl.py. No es una credencial SSH ni autorización de cloud.

OPL2: magic4f504c02, LE32 longitud XOR0xa7b3c5d1, LE32 CRC32 del ASCII punteado, cuerpo XOR ROTL8(195,i%8) XOR(i&255). El importador también admite el sobre punteado sin OPL y legado Base64 con nonceBE32/longitudBE32 y XOR/rotación de pf.n. Para impedir basura anexada se exige longitud exacta; el original legado aceptaba sufijos. El legado no autentica.

Problema anterior: tnl.py ya conocía OPL2, pero su lector XML por líneas eliminaba restricciones/valores vacíos, renombraba campos y podía perder XML compacto o multilineal. El nuevo lector del servidor conserva todas las propiedades, XML entities estándar, Unicode, CR/LF y cadenas JSON como valores, sin quitar restricciones. XML externo/ENTITY/DOCTYPE no estándar y claves duplicadas se rechazan. El exportador oficial puede sustituir sshUser/sshPass por vacíos y sshCredsRedacted1; no se inventan ni recuperan valores que no están en el archivo.

La matriz C0 de240 rutas y tnl.py permanecen intactos. La ruta tnl del worker usa overlay C8, conservando el total256. La variante GCM histórica C0, con disposición distinta, se selecciona antes de descifrar y usa sus claves/1000iteraciones/128bits ya registradas; un tag moderno fallido nunca entra en ese lector. Se mantiene el golden histórico Host/Port. La declaración pública sigue indicando capacidad offline heredada; la mejora build61 corresponde al servidor. No se modifica Android.

Verificación: OpenOracle.java usa Java Properties y JCA independiente para generar OPL2, punteado y legado sintéticos. Python y worker coinciden; se prueba un payload de5000líneas, flags de autor, campos desconocidos/vacíos, longitudes/CRC/tag/DOCTYPE corruptos. No se recibió archivo exportado desde un teléfono: VERIFIED_SYNTHETIC; falta certificación real por archivo, sin afirmar VERIFIED_REAL ni exportador compatible.

## Catálogo SSH

ba0.java usa GET público https://api.roosterkid.com/api/opentunnel/servers/. Respuesta real200/1515bytes: status200,count7,servers con city,country,countryCode,dnstt,hostname,premium,serverName,status. Se conserva el documento entero y su esquema; ver catalog-proof.json, comparación con json.loads y worker real.

No contiene username/password. La app obtiene credenciales individuales por un POST separado action=generate y seguimiento de su propia cuenta. No se llamó ese POST, no se consultaron usuarios ajenos ni APIs privadas de archivos cloud. El catálogo se presenta como «OpenTunnel · Servidores SSH» y devuelve una advertencia precisa. La lista genérica de protocolos de PublicServersActivity no se mezcla ni sustituye. No hay dos solicitudes ocultas para esta entrada.

Icono PNG original192×192,4978bytes; sin redibujar. MD conserva WebP original y su MIME real mediante la misma API, manteniendo PNG para el resto. No implica ninguna validación de conexión VPN.
