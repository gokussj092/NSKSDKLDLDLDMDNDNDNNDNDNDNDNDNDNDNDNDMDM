# Evidencia de ANY VPN build 40

Muestra autorizada: `ANY VPN_16kb-page-size.apks`, paquete
`com.markvpnpro.pinas`, versionName `16kb-page-size`, versionCode 40.

- APKS SHA-256: `f8e137b582049b00e74cd204df92d9dd18fdb097c3e95621a19ae687cb56a68a`.
- Base APK SHA-256: `a68ba7df1ae86056ec4d3e429ebcb7de17cbcbcbea55f43290cfdc8213b24b73`.
- DEX3 SHA-256: `af631a1d91feeeabe6ca81f10c1f230ebbb04716d3d9007c727bab38fb180e38`.

Misma rama y PR #99, HEAD previo `b83419c`. El usuario ahora solicita añadir
también Speicers al catálogo: sustituye la instrucción previa de mantenerlo
privado. No autoriza una fusión, despliegue, APK ni publicación de novedades.

JADX 1.5.6 verificado por el bootstrap existente termina con 31 errores
generales. No se afirma descompilación completa. `random_strings.py` resolvió
6694 llamadas explícitas de 126 archivos de com/tknetwork usando la
implementación Java Random de `com.panda912.muddy.ObfuscatedString`.

## Catálogo

`MainBaseActivity.getJSONObject()` lee `Servers.js` privado y, cuando no existe,
abre `new c_11().conf` mediante `UtilsKey.Parser.parseToString`. La constante
del DEX decodifica a JSON 1.1, 12 servidores, 46 redes y sus metadatos completos.
El asset `tk.js` no es el catálogo consumido por esta ruta; no se usa como
evidencia de compatibilidad ni se intenta adivinarle otra clave.

`UtilsKey.Parser.parseToString` se confirmó en sus cuatro instrucciones Dalvik:
lee `UtilsKey.key`, llama a AESHelper.decrypt y devuelve el texto. Clave fija
red1987, SHA-256 UTF-8 directo, CBC con IV cero y PKCS7. No usa la ruta `a`
con clave ir1987, que se observa en una función separada del túnel.

El catálogo protege 13 campos por servidor, cuatro por red y dos metadatos.
`ServerActivity` confirma etServerAddress, etEndpoint, etPublicKey,
etPrivateKey, etPreSharedKey, etAllowedIPs, vaddress y vhost como cifrados.
ActivityUi/VPNUtil confirman Payload, Squid, SNIHost, vsni y los campos SSH.
CustomCa, P_CustomCa, DNS y otros campos no se abren como si fueran cifrados.

La URL usada por `ActivityUi.checkResources` procede de `config_url` y pasa
por 26 sustituciones Unicode a ASCII. Se recuperó la URL exacta, no se usó
como destino la constante histórica data_url de c_11. El GET de
JsonManager.ServerUpdate usa el agente por defecto de OkHttp, confirmado en
`okhttp3.internal._UtilCommonKt.userAgent`. Con ese agente respondió 200,
118208 bytes: versión 5.84, 13 servidores y 91 redes.

El downloader acepta únicamente la constante comprobada. No se continúan
URLs recibidas dentro de JSON ni redirecciones, y no se llama a account_api
o a rutas de autenticación/caducidad/freeze. La implementación de broker
conserva TLS, IP pública fijada, límites y políticas de red existentes.

## Archivos

`FileUtilKt.writeToFile` añade `.dtk` y cifra con UtilsKey.Parser.encrypt.
`ActivityUi.attemptExportNetwork` construye un contenedor cuyo campo network
es JSON en forma de cadena, y lo entrega a esa función. El método tiene 151
instrucciones Dalvik. `ExportActivity` y ActivityUi descifran el exterior y
procesan los campos server y network; no reciben contraseña del usuario.

`attemptExportServer` también tiene 151 instrucciones y usa encrypt antes
de `new JSONObject`: esa anomalía pertenece al APK. La prueba combinada es
un contenedor sintético válido para el importador; no certifica el exportador
de servidor. No se ejecutó Android ni se aportó un .dtk real.

El manifest registra file/content; no se identificó texto propietario ni
cloud por token. Las importaciones de protocolos comunes no se convierten
en nuevos esquemas inventados. Las bibliotecas nativas no son necesarias
para estas primitivas Java ni para el runtime Python.

Herramientas y referencia JDK quedan en Git; APK/SO/DEX, inventarios de
cadenas, catálogos y resultados privados quedan fuera del repositorio.
