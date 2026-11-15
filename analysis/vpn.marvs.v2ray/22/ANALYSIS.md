# RH Tunnel Secure (Marvs V2Ray) RHV1 — ANALYSIS

- Paquete: `vpn.marvs.v2ray` · versionCode: 22 · versionName: `RHV1`
- Observado: 2026-11-15 · Estado del expediente: **PARTIAL**
- Muestra: RH_Tunnel_Secure_RHV1_APKPure.xapk, 53253787 B, SHA-256 `cc060ad5cb0d5f78305d3afc566d579f7d675b56eb97fce112650b789b4adf47`

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

Fork de v2rayNG con nucleo Sandok/Ultra (AndroidLibXrayLite, Go, proyecto BB Tunnel Pro); cadenas ofuscadas con LSParanoid. Catalogo: GET simple de un archivo de texto estatico, sin cuerpo ni hash, User-Agent Go-http-client/1.1, sin auth. Respuesta HTTP 200 text/plain, cuerpo de una sola linea Base64 (325.897 B el 2026-11-15, byte-identico entre peticiones y entre User-Agents) con una letra ASCII aleatoria insertada en el indice 3 del Base64 DESPUES de codificar (por eso el cuerpo mide 1 mod 4). Sobre Argon2id (t=3, m=8192 KiB, hilos=1, 32 B) + AES-256-GCM (AAD=salt): Base64(salt[16] || nonce[12] || ct || tag). Dos contrasenas de formato en libgojni.so .rodata, recuperadas por desensamblado de ESTE APK y verificadas abriendo los sobres reales; sus valores viven SOLO en los scripts operativos: la clave en vivo (23 B) abre el catalogo en vivo y los .bbtun exportados; la clave de campos (21 B) abre el asset incluido y cada campo protegido dentro del catalogo. JSON con esquema Sandok/Ultra (Version, ReleaseNotes, Telegram, WhatsApp, Facebook, credenciales por defecto, DefaultOVPNCert, Servers[], Networks[]); sin marcador gratis/premium. Archivos .bbtun (manifest application/x-bbtun, .*\.bbtun, ConfigFileParser): al importar la app prueba Libv2ray.parseConfig() y si falla el Go DO() (clave de campos); al exportar cifra el JSON Gson del perfil con Encrypt() (clave en vivo) con la letra marcadora en el indice 3. El script prueba AMBAS claves. CORRECCION durante la verificacion: ambos scripts traian el docstring de Marvs SSH copiado (metodo POST /api/t20/ y claves equivocadas); se reescribieron con el metodo BB real.

## Capas de cifrado: observacion / hipotesis / verificacion

Observacion: nada se reutilizo de las hermanas (Marvs SSH POST /api/t20/, MM Tunnel POST /api/mmtunnel/) sin verificarlo en ESTE APK: endpoint, claves y parametros Argon2 se recuperaron por desensamblado de este libgojni.so (32.763.152 B, nucleo BB Tunnel Pro, distinto build que los de Marvs SSH y MM Tunnel). Hipotesis: ninguna pendiente en catalogo. Verificacion: cuerpo en vivo abre con la clave en vivo (2.74, 23/211); campos 1.496/1.496 con via rapida; asset abre con la clave de campos (tag GCM autentico, 1.24, 10/32); muestra .bbtun abre y el JSON es identico al original. Un descifrado del sobre tarda ~15-20 s en stdlib puro; los 1.496 sobres de campo necesitan la via rapida (argon2-cffi + PyCryptodome, ~0,3 s por sobre).

## Catalogo en vivo (verificado)

Version 2.74, 23 servidores, 211 redes; campos protegidos 1.496/1.496 descifrados (via rapida); 50 valores que no abren son textos Info en claro, no sobres. Asset incluido: Version 1.24, 10 servidores, 32 redes, 314/314 campos.

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

- Falta un .bbtun REAL exportado por la app en un telefono para confirmar el decodificador de archivos de extremo a extremo (hoy solo muestra sintetica sellada con el mismo metodo).
- Los iconos de red se descargan de una ruta de iconos del mismo dominio (no forma parte del catalogo).
- En Play y APKPure figura como RH Tunnel Secure (antes Marvs V2Ray).

## Preguntas sin resolver

- .bbtun real exportado por la app RHV1.
- Re-verificar cuando el servidor sirva una version nueva del catalogo (hoy 2.74) o la app se actualice (hoy RHV1 / build 22).
