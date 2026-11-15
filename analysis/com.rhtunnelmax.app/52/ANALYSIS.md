# RH Tunnel Lite 39.0.1 — ANALYSIS

- Paquete: `com.rhtunnelmax.app` · versionCode: 52 · versionName: `39.0.1`
- Observado: 2026-11-15 · Estado del expediente: **PARTIAL**
- Muestra: RH_Tunnel_Lite_39.0.1_APKPure.xapk (SHA-256 y SHA-1 coinciden con APKPure), 46408621 B, SHA-256 `9709ede7d75180d3a8a3bf3b3f52500ef07902a06501cf62b63310b259c67914`

## Objetivo

Documentar el metodo de descifrado de catalogo, archivos y textos de esta
app para SP-DECODE, con evidencia reproducible y sin secretos, como paso
previo (Fase 1) a su integracion en el parche de 20 apps.

## Como se obtuvo la muestra

XAPK publico descargado de APKPure y verificado por SHA-256/SHA-1 contra
lo publicado (ver TESTING.md de origen). El APK se extrajo (base + splits
de ABI/idioma/dpi); las librerias nativas viven en el split arm64. No se
guarda ningun APK ni binario en este expediente: solo hashes.

## Metodo

Blob (sabconfig.hs y el archivo del catalogo): empaquetado chino de 12 bits (cada valor + 0x4E00 a caracter CJK) + AES/CBC/PKCS7 con clave SHA-256 de la clave de texto e IV de 16 ceros, aplicado DOS veces (util.decrypt x 2). El texto resultante lleva el prefijo Telegram@noob_xman antes del '{' del JSON. Campos sensibles del JSON (hosts, IPs, usuarios, claves, enlaces vless/vmess, certificado OpenVPN, config_url/cloud_get_api): XXTEA con delta NO estandar (distinto del clasico 0x9E3779B9) en Base64 estandar, con la misma clave de texto que el AES. V2rayID va cifrado dos veces con XXTEA. El certificado OpenVPN (Ovpn_Cert, XXTEA) es una plantilla completa de cliente OpenVPN. La app guarda el asset como filesDir/Servers.js y mezcla Servers y HTTPNetworks cuando Version es mayor. Enlaces de texto (por portapapeles; NO hay scheme en el manifest): SabDev:// + XXTEA-Base64 del JSON de un servidor (17 campos); shanS:// + XXTEA-Base64 del JSON de una red (23 campos). El catalogo se descarga con la API de GitHub con token Bearer embebido en la APK (sin token la API responde 404 y la URL raw directa tambien 404); el token vive SOLO en el script operativo.

## Capas de cifrado: observacion / hipotesis / verificacion

Observacion: cuatro rutas de actualizacion (directa y por proxy V2Ray) usan el mismo endpoint; User-Agent SabrinaPro-App. Hipotesis: ninguna pendiente en el descifrado. Verificacion: asset integrado abre (v200.8); catalogo en vivo abre (v200.38, HTTP 200, 489.378 B); los 17 servidores y las 200 redes descifran campo por campo; Ovpn_Cert descifra a plantilla completa; V2rayID del servidor 7 descifra en dos rondas. Fallo encontrado y corregido durante el trabajo: el empaquetado chino puro acumulaba bits sin limite y tardaba ~20 s; tras enmascarar los bits consumidos tarda ~0,17 s con pycryptodome. El fallback AES puro tarda ~26 s en el blob integrado (por encima del tope de 20 s del worker: usar el entorno con pycryptodome).

## Catalogo en vivo (verificado)

Version 200.38, 17 servidores (7 paises segun FLAG; OpenVPN 8, V2Ray 7, DNSTT 2), 200 redes/payloads (ovpn 172, v2ray 14, udp 13, dnstt 1; cf 126, ws 69, http 5); 134 redes con payload. Asset integrado: Version 200.8, 17 servidores, 181 redes.

## Herramientas, por orden

1. Extraccion del XAPK y lectura del manifest/assets (apktool/androguard).
2. Descompilacion del DEX con jadx; lectura de cadenas y clases de red.
3. Desensamblado de `libgojni.so` (capstone; scripts en `tools/`) para
   localizar las funciones de cifrado y las constantes de formato.
4. Construccion del script operativo (solo-stdlib, con fallback puro) y
   prueba contra descarga real y contra el asset incluido.
5. Verificacion de la regla SP-DECODE 2026-11-15: el JSON de resultado
   lleva solo los datos del catalogo, todo descifrado, sin APIs de descarga.

Las versiones de las herramientas estan en `DEPENDENCIES.md`; las no
registradas en los logs de origen figuran como UNKNOWN, no inventadas.

## Evidencia de rutas remotas

Descarga en vivo verificada (ver `RESULTS.md` y `TESTING.md` de origen).
No se reproduce aqui ningun endpoint de descarga ni token: la ruta exacta
vive en el script operativo y en el registro supplied-integrations. El
expediente registra conteos reales (servidores/redes/campos) y el estado
de cada via, no URLs.

## Alcance real

El estado por via esta en `MANIFEST.json` (`targets`). Un catalogo estatico
incluido que abre NO certifica la descarga remota, y viceversa: aqui ambas
vias se probaron por separado donde el material lo permitia. Lo sintetico
se marca `VERIFIED_SYNTHETIC`, nunca `VERIFIED`.

## Auditoria HMAC de conexion (politica 2.2)

- **file_catalog_integrity**: NOT_OBSERVED — Sin MAC: AES-CBC + XXTEA; la integridad es implicita (relleno PKCS7 y parseo JSON). No se observo HMAC.
- **cryptographic_derivation**: NOT_OBSERVED — Clave AES = SHA-256 de la clave de texto; sin HMAC en la derivacion.
- **vpn_transport**: NOT_OBSERVED — No se reviso el transporte VPN de esta app.
- **connection_authentication**: NOT_OBSERVED — No se observo HMAC de autenticacion de conexion. El token Bearer es autorizacion de la API de GitHub, no autenticacion de conexion VPN.

La mera presencia de una libreria HMAC no confirma nada; solo se confirma
lo observado arriba. No se guardan valores de claves ni entradas/salidas
de hooks.

## Cambios frente a builds previos

Sin build previo de este mismo paquete en el expediente. Las diferencias
con apps hermanas de la misma familia estan documentadas en el README de
origen (metodo, endpoint y claves verificados en ESTE APK, no reutilizados
sin verificar).

## Limitaciones

- Falta un .hs REAL exportado por la app para confirmar el envoltorio exacto de exportacion (save() sin llamadas visibles en 39.0.1; el .hs sintetico contiene un enlace SabDev://).
- Falta un archivo real protegido (servidor/red con usuario/clave propios del usuario).
- Si la descarga devuelve 401, el desarrollador roto el token: hay que extraer el nuevo de la APK actualizada.
- No se probo en un telefono real con la app instalada.
- COLISION DE SUFIJO .hs: el sufijo .hs lo comparte JK VPN (com.fastvpn.jk), con un formato distinto (Tink Streaming AEAD). NO resuelto en este expediente: la decision del discriminador esta pendiente en la fase de discriminadores del parche. Este expediente documenta solo el formato RH.

## Preguntas sin resolver

- Envoltorio exacto del .hs exportado por la app (pendiente de muestra real).
- Discriminador .hs compartido con JK VPN (decision pendiente, fase de discriminadores).
