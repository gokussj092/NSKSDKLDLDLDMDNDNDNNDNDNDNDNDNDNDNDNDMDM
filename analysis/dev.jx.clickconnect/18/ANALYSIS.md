# VLX Tunnel VPN VLX v14 — ANALYSIS

- Paquete: `dev.jx.clickconnect` · versionCode: 18 · versionName: `VLX v14`
- Observado: 2026-11-15 · Estado del expediente: **PARTIAL**
- Muestra: VLX_Tunnel_VPN_VLX_v14_APKPure.xapk (SHA-256 y SHA-1 coinciden con APKPure), 47374199 B, SHA-256 `973ec793bb9e2374c073c2c9199b38e70989ddccd17d34ebd4080c372095a548`

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

Fork de v2rayNG con nucleo Sandok/Ultra (AndroidLibXrayLite, Go). Catalogo: GET simple de un archivo estatico, sin cuerpo ni hash, con User-Agent obligatorio (ver script operativo): el servidor responde HTTP 404 a Go-http-client/1.1 y al UA por defecto de curl, y HTTP 200 solo con el UA de la app (verificado 2026-11-15). Respuesta HTTP 200, Content-Type text/html; charset=UTF-8, cuerpo de una sola linea Base64 (1.082.108 B el 2026-11-15, byte-identico entre peticiones con ese UA), SIN letra marcadora (el cuerpo mide 0 mod 4; no hay randomLetter en el binario, a diferencia de Marvs). Sobre Argon2id (t=3, m=8192 KiB, hilos=1, 32 B) + AES-256-GCM (AAD=salt): Base64(salt[16] || nonce[12] || ct || tag). Dos contrasenas de formato en libgojni.so .rodata de ESTE APK, recuperadas por desensamblado de decrypt()/Encrypt()/EO()/DO() y verificadas abriendo los sobres reales; sus valores viven SOLO en las constantes de los scripts: la clave en vivo (22 B) abre el catalogo vivo; la clave de campos (20 B) abre el asset y los 4.518 sobres de campo. JSON con esquema Sandok/Ultra. Archivos .vlx (manifest application/x-vlx, .*\.vlx, ConfigFileParser): al importar, la app prueba el sobre con la clave en vivo y, si falla, con la clave de campos; al exportar cifra el JSON Gson del perfil con la clave en vivo. El script prueba AMBAS claves y descifra los sobres de campo dentro del perfil. Las protecciones (contrasena, HWID, bloqueo de red) viven DENTRO del JSON descifrado. En Play NO se llama ClickConnect (el paquete es dev.jx.clickconnect). Archivos .sks excluidos por indicacion de Pedro (esta app tampoco los usa).

## Capas de cifrado: observacion / hipotesis / verificacion

Observacion: URL y User-Agent recuperados de libgojni.so .rodata y de AndroidLibXrayLite.CU; decrypt/EO/DO/Encrypt localizados por desensamblado. Hipotesis: ninguna pendiente en catalogo/archivos. Verificacion: descarga con el propio script (venv, --workers 4): 23.759, 19/721, campos 4.518/4.518, 0 fallos; cuerpo byte-identico entre peticiones; muestra.vlx abre con la clave en vivo y es identica al original (con el Payload interior descifrado). Un descifrado del sobre tarda ~15-20 s en stdlib puro; los 4.518 sobres de campo necesitan la via rapida.

## Catalogo en vivo (verificado)

Version 23.759, 19 servidores (todos con host no vacio), 721 redes; campos protegidos 4.518/4.518 descifrados (via rapida). Asset: Version 1.01, 1 servidor, 1 red, 17/17 campos.

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

- **file_catalog_integrity**: NOT_OBSERVED — Integridad por tags AES-256-GCM (AEAD), no por HMAC.
- **cryptographic_derivation**: NOT_OBSERVED — Derivacion por Argon2id; sin HMAC en la derivacion.
- **vpn_transport**: NOT_OBSERVED — No se reviso el transporte VPN de esta app.
- **connection_authentication**: NOT_OBSERVED — No se observo HMAC de autenticacion de conexion.

La mera presencia de una libreria HMAC no confirma nada; solo se confirma
lo observado arriba. No se guardan valores de claves ni entradas/salidas
de hooks.

## Cambios frente a builds previos

Sin build previo de este mismo paquete en el expediente. Las diferencias
con apps hermanas de la misma familia estan documentadas en el README de
origen (metodo, endpoint y claves verificados en ESTE APK, no reutilizados
sin verificar).

## Limitaciones

- Falta un .vlx REAL exportado por la app en un telefono.
- El servidor exige el User-Agent exacto de la app (con otro UA responde 404).

## Preguntas sin resolver

- .vlx real exportado por la app.
- Re-verificar cuando el servidor sirva una version nueva del catalogo (hoy 23.759) o la app se actualice (hoy VLX v14 / build 18).
