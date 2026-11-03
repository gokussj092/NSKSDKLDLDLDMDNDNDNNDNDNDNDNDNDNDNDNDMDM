# ALSAHER VIP — investigación Cloud del build 2

2026-11-03, America/Tijuana. Base Git fc9b9d3fcea11cb2eb0159107d2aaf43c4255390,
rama `fix/http-jireh-current-method`. El propietario pidió repetir la integración
de catálogo con la APK indicada, sin modificar Android ni esperar su compilación.
Se aplicaron METHOD_EVIDENCE_POLICY y la paridad de descarga original.

## Observación y procedencia

APK `https://archive.org/download/ALSAHERVIP/ALSAHERVIP.apk`, 64923898 bytes,
SHA256 `5b68209e3d4a9f4703d678dedeaa07f00663fa9aaa279360b437db7976432a1a`.
ZIP íntegro. Androguard confirma `com.alsaher.vip`, ALSAHER VIP,1.1/code2.
No se afirma que sea la última versión oficial; es el binario seleccionado.

Se extrajeron tres DEX, el icono PNG original y `assets/mtkConfig.zip`.
Este último es un ZIP sin contraseña con `mtk.hs`. Libh2 se extrajo para
inventario inicial; no se ejecutó ninguna APK/SO. El catálogo es Java y no
necesitó emulación nativa ni acceso a un dispositivo Android.

El actualizador `OpenVPNClient` crea `checkUpdate` con una URL raw GitHub
literal en dos puntos (líneas439 y1359 de la salida JADX). `FetchJSON` usa
`new OkHttpClient()` y GET sin cabeceras de autenticación. BridgeInterceptor
aporta la constante `Util.userAgent = okhttp/4.12.0`. La CLI reproduce ese
User-Agent y conserva HTTPS, sin cookies ni endpoints aportados por el cliente.

## Método confirmado

`FileUtils.showJson` llama a `XxTea.decryptBase64StringToString`, luego `_De`.
`_De` resta el valor numérico de `getPass()` dos veces a cada char UTF16.
La rutina XXTEA usa delta772515655, palabras little-endian, clave de16 bytes
ajustada como el original y longitud final comprobada. Clave y desplazamiento
coinciden exactamente con la familia ZiG existente. Se reutiliza esa primitiva;
no se modifica el motor compartido ni se duplica su implementación.

El censo de cadenas descifrables del remoto confirmó9 ubicaciones: config_url,
ServerIP/ServerCloudFront/ServerHTTP/ProxyHost en Servers y payload/SquidProxy/
SSLSNI en las listas HTTP/SSL. Se contrastan también todos los contextos
conocidos de la familia, incluidos los vacíos y aliases, con referencia Java.
JSONsettings contiene preferencias planas y se conserva íntegro.

La primera apertura con ZiG fue una comprobación de familia. La adaptación
ALSAHER añade los aliases cloud_get_api/cloud_post_api y exige listas HTTP/SSL
y JSONsettings del documento observado. Esos aliases están vacíos realmente;
los vectores sintéticos cubren su caso no vacío sin anunciar otro servicio.

## Verificación real completa

| Fuente | Bytes cifrados | Versión | Servers | HTTP | SSL | Campos cifrados/distintos |
| --- | ---: | --- | ---: | ---: | ---: | --- |
| Incluido |72096|9.9.9|4|4|1|29/13|
| Remoto y descarga CLI |80552|9.9.58|14|3|9|76/33|

Ambos documentos completos coinciden con Java, CLI y worker. La descarga
operativa hizo GET real, verificó HTTP200 y produjo el mismo objeto remoto.
No hay fallback al incluido ni mezcla de versiones. Los hashes y recuentos
sanitizados están en generated; no se incluye ningún perfil real en Git.

Node directo devolvió REMOTE_NETWORK_DENIED. `probe_node.mjs --replay` pasó
por broker y contrato con bytes/resultados reales pero HTTP/DNS simulados.
No equivale a una descarga Node real ni a prueba del VPS. Esa parte sigue
pendiente; no se cambiaron proxy, DNS, TLS o protecciones para sortearla.

## Fallos y límites conservados

- El entorno de análisis anterior ya no tenía sus dependencias instaladas;
  se recreó uno aislado y se fijaron las42 versiones reales en el lock.
- JADX1.5.6 terminó exit3 en los tres DEX:14/16/8 errores. FileUtils,
  XxTea, checkUpdate y el actualizador relevantes sí están presentes; el
  pseudocódigo parcial no se considera prueba de compilación. La igualdad
  criptográfica/documental independiente es la validación del lector.
- La primera importación local del motor compartido falló por faltar
  HTTP_FenixVPN/field_names.json en el checkout parcial; se recuperó ese archivo
  existente, sin modificarlo. No fue un fallo de descifrado.
- Un comando exploratorio de tail tuvo un error de sintaxis; se corrigió
  la lectura del log. No alteró muestras ni resultados.
- 9 Python y38 Node correctas. No pruebas Android, compilaciones, merges o VPS.

## Integración

ALSAHER_VIP codec/CLI, registro de worker y engine, broker fijo, contrato de
documento completo, ficha/icono original y control C12 individual. Fuente64/
60 fichas. Sin secretos nuevos, cambios Compose, formatos nuevos ni Android.
El PNG es el mismo `res/HI.png`:1024x1024/205869 bytes,
SHA256 `54f97101174f2fa5d53947ede0e628ea19caa87f7fd664652ff63f69aa325333`.

Estado VERIFIED_REAL para la descarga Python y el descifrado; integración de
código terminada. El despliegue/Node real en VPS sigue separado y pendiente.
