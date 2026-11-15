# MT KING NET 15.35.2 — ANALYSIS

- Paquete: `app.mtkingnet.buildd` · versionCode: 25 · versionName: `15.35.2`
- Observado: 2026-11-15 · Estado del expediente: **PARTIAL**
- Muestra: MT_KING_NET_15.35.2_APKPure.xapk (SHA-1 coincide con APKPure; APKPure no publica SHA-256 para esta variante), 47634903 B, SHA-256 `122de64e293e5f5311621d513cfbaa28d24d19ff73af692a7da3dc7bf89939f8`

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

Misma familia ISVSoft que TSC VPN Proxy (mismo worker, misma clave de formato, distinto identificador de app). Descarga GET al worker con User-Agent ISVSOFT-CloudSync/2.0, X-ISV-Timestamp (segundos unix), X-ISV-Nonce (UUID sin guiones, 32 hex) y X-ISV-Signature = HMAC-SHA256(clave de formato, "<timestamp>:<nonce>:<encodedPath>") en hex, donde el path firmado es el encodedPath SIN la query. Sin estos headers el worker responde 403 (sin UA: Unauthorized Client User-Agent; con UA pero sin firma: Missing Native App-Proof credentials; firma invalida: Invalid Native App-Proof signature; firma vieja: App-Proof handshake expired). Respuesta JSON {meta, servers, tweaks, settings} donde cada valor sensible es "enc:<base64url>" y se abre con AES-256-GCM, clave fija de formato (32 B ASCII, misma clave de la familia ISVSoft), nonce = primeros 12 B, tag = ultimos 16 B, sin AAD. Sobre: base64url(nonce[12] || ct || tag[16]). La clave se verifico funcionalmente para esta app: abre los assets incluidos y el catalogo en vivo (1.103 valores enc: en type=full). Archivos locales: la app guarda cached_cloud_bundle.json en filesDir tras cada descarga (misma estructura que la respuesta del worker) y los assets servers.json, tweaks.json y settings.json; los perfiles de usuario viven en una base Room interna, no en archivos. Sin formato propio de perfil exportable. Nube (config share): mismo worker, POST api/v1/config/share y GET api/v1/config/share/{code}; requiere registro de dispositivo (POST api/v1/device/register) + creditos (GET api/v1/device/credit).

## Capas de cifrado: observacion / hipotesis / verificacion

Observacion: la clave de formato no aparece literal en libisvcrypto.so de esta app (se deriva en runtime; la .so difiere en hash de la de TSC) pero el metodo es el mismo y la clave abre todo. Hipotesis: ninguna pendiente en catalogo/archivos. Verificacion: en vivo dos veces (type=full 331.294 B y type=servers 68.820 B, mismos 80 servidores); cached_cloud_bundle.json local abre identico al descifrado en vivo; assets abren (v1.0.0). Nube probada solo con codigo inventado: GET .../share/TEST1234 responde HTTP 404 (el endpoint existe; el codigo no). GET device/credit con dispositivo inventado cerro la conexion sin respuesta (no concluyente).

## Catalogo en vivo (verificado)

Version 21.31.299, 80 servidores (80 online), 367 tweaks (127 con payload HTTP, 211 con SNI), settings con predefinedCredentials (ssh, openvpn, v2ray, hysteria, shadowsocks, wireguard) y 1 certProfile. type=servers devuelve los mismos 80 servidores sin tweaks/settings. Assets del APK: v1.0.0, 9 servidores, 11 tweaks.

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
- **cryptographic_derivation**: NOT_OBSERVED — Sin HMAC en la derivacion de la clave de formato (clave fija verificada funcionalmente).
- **vpn_transport**: NOT_OBSERVED — No se reviso el transporte VPN de esta app.
- **connection_authentication**: NOT_OBSERVED — Existe HMAC-SHA256 App-Proof (X-ISV-Signature sobre '<timestamp>:<nonce>:<encodedPath>') pero es autenticacion de la PETICION al worker del catalogo, verificada por el worker (403 sin ella). NO es autenticacion de conexion VPN: no se observo ningun HMAC que autorice el establecimiento de la conexion VPN.
- **api_request_authentication**: CONFIRMED — HMAC-SHA256 App-Proof confirmado: el worker responde 403 con mensajes distintos segun falte el UA, la firma, o la firma sea invalida o vieja. Ambito: peticion al catalogo, no conexion VPN.

La mera presencia de una libreria HMAC no confirma nada; solo se confirma
lo observado arriba. No se guardan valores de claves ni entradas/salidas
de hooks.

## Cambios frente a builds previos

Sin build previo de este mismo paquete en el expediente. Las diferencias
con apps hermanas de la misma familia estan documentadas en el README de
origen (metodo, endpoint y claves verificados en ESTE APK, no reutilizados
sin verificar).

## Limitaciones

- Falta un cached_cloud_bundle.json REAL de un telefono (la estructura es la misma por codigo, pero no hay muestra real).
- El flujo cloud share (subir/descargar + registro de dispositivo + creditos) NO esta verificado en vivo: necesita un dispositivo registrado.
- Falta un enlace real pegado en la app para confirmar el parseo del nucleo v2rayNG con sus servidores.
- La app no tiene esquema URI propio ni deep link (solo MAIN/LAUNCHER); la importacion de enlaces es por pegado.

## Preguntas sin resolver

- Muestra real de cached_cloud_bundle.json de telefono.
- Flujo cloud share completo (registro + creditos + subida/descarga).
