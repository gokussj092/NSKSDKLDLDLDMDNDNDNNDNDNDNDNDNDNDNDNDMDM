# RoVPN (com.mobileapp.rovpn, 7.6) — catálogo, archivos profile.json y esquemas de texto

App: **RoVPN**, paquete `com.mobileapp.rovpn`, versionCode **76**,
versionName `7.6`, minSdk 32, targetSdk 34. APK analizado: XAPK de APKPure
con la versión de Google Play (7.6), SHA-256 del XAPK
`d41033a0e676d9cb000da78ad0a8820ae4914df6469aaf1c250e4b6955fa2a4f`
(`browser-download-20261113T211903.482523912Z-14-ROVPN_7.6_APKPure.xapk`).
Fecha de trabajo: 2026-11-13. Alcance: **catálogo + archivos profile.json
+ esquemas de texto**, desde cero — el repo SP-DECODE (rama
`feat/nuevas-integraciones`) no tiene cobertura de RoVPN (86 carpetas de
apps, ninguna RoVPN). No se modificó el repo SP-DECODE ni se subió nada
a Git. No se guardan ni se imprimen en este documento valores
descifrados, contraseñas, claves de usuario ni datos sensibles: solo
recuentos, hashes y estructura.

## Estructura de la app

- Fork de **v2rayNG**, ofuscado con R8 (el código de la app vive en 74
  clases bajo `com.mobileapp.rovpn`; el resto son librerías y paquetes
  ofuscados de una letra). Cadenas con **LSParanoid** (`Lku2;`,
  método `n(J)` con tabla `String[] a`): 1.087 cadenas resueltas con el
  deobfuscator de referencia, 0 errores (ver `work/resolve_ku2.py` y
  `work/deob_strings.txt`).
- Base APK sin `.so`; las 10 librerías nativas están en
  `config.arm64_v8a.apk`: `libapi-cpp.so` (4.536 B), `libgojni.so`
  (30,7 MB, núcleo Go/Xray), `libv2ray.so`, `libhysteria.so`,
  `libovpncli.so`, `libtun2socks.so`, `libdns.so`, `libpdnsd.so`,
  `libmmkv.so`, `libdatastore_shared_counter.so`.
- `libapi-cpp.so` expone 3 métodos JNI en `MainDetail`: `a()` → URL de
  config antigua, `b()` → blob de 128 caracteres (material de clave),
  `c()` → URL de ping. **Solo `b()` tiene llamadores desde Java**
  (`MainActivity.onCreate`); `a()` y `c()` no se usan.
- `xe1.b()` es un anti-tamper de firma: lee `/proc/self/maps`, toma la
  ruta real de `base.apk` y comprueba que su SHA-256 esté entre dos
  hashes permitidos; solo entonces `ro3` (MainApplication) siembra los
  valores por defecto de `key_url` y `key_secured` en
  EncryptedSharedPreferences.

## Método exacto del catálogo

### Descarga

- **Endpoint activo:** `https://iovpn.me/app/config/rooojshsh727272h3n.php`
  (GET). URL fija sin parámetros, sin token de ruta. Es el valor por
  defecto de la preferencia `key_url` (constante LSParanoid
  `ku2.n(-34070443699437L)`); si el usuario cambia `key_url`, la app
  descarga de esa URL en su lugar.
- **Dónde vive la URL en el APK:** `ro3.<init>` (rama por defecto, cuando
  `xe1.b(context)` es true) escribe `key_url` y `key_secured`
  (`ku2.n(-27761136741613L)`). `nq0` (update check, desde
  `MainActivity.onCreate`) lee `key_url` y hace el GET con OkHttp
  (`gg0`: timeouts 5 s + 5 s, sin cabeceras propias, User-Agent por
  defecto de OkHttp).
- **Petición replicada:** GET plano, cabeceras `User-Agent: okhttp/4.12.0`,
  `Accept-Encoding: identity`, `Connection: keep-alive`. **Sin User-Agent
  de OkHttp el endpoint responde 403** (verificado: el User-Agent por
  defecto de Python-urllib da 403). Sin autenticación, token ni firma.
- **Incidencia de red (igual que Fat Tunnel):** el endpoint responde con
  `Transfer-Encoding: chunked` y sin Content-Length; `urllib` añade
  `Connection: close` y la descarga se corta a mitad (18.791 bytes de
  54.128, determinista) a través del proxy de salida de esta máquina.
  `fetch_catalog` usa `http.client` directamente y nunca envía
  `Connection: close`; un cuerpo truncado se reintenta con un GET nuevo
  (hasta 6 intentos) y el tag GCM de `decode()` es lo que prueba que un
  cuerpo está completo. El servidor **no** acepta `Range` (416).

### Descifrado de la respuesta

Es Google Tink **AesGcmHkdfStreaming** (clases `x5`/`w5`/`gg1`/`dk1`
en el DEX):

1. **Base64 estándar** del cuerpo completo (54.128 B en la prueba viva).
2. Cabecera de 40 bytes: byte 0 = 40 (tamaño de cabecera), bytes 1..32 =
   salt aleatoria, bytes 33..39 = noncePrefix aleatorio (7 bytes).
3. IKM = **PBKDF2-HmacSHA256** (contraseña de formato `key_secured`,
   salt UTF-8 `MY_APP_FIXED_SALT_V1`, 100.000 iteraciones, 32 bytes).
4. Clave de segmento = **HKDF-SHA256** (ikm, salt de cabecera,
   info = `MY_SECURE_JSON_STREAM_V1`, 32 bytes).
5. Segmentos: el primer segmento de cifrado mide 4.056 bytes
   (4.096 - 40 de cabecera) y los siguientes 4.096; cada uno es
   **AES-256-GCM** con nonce = noncePrefix || nº de segmento (BE32) ||
   flag último (1 byte), sin AAD, tag de 16 bytes. Segmento de texto
   plano: 4.040 bytes el primero, 4.080 los siguientes.
6. Resultado: **JSON UTF-8 completo** con `Version`, `Message`,
   `Servers[]`, `Networks[]` y `setOpenVPN` (config OpenVPN por defecto).

- La contraseña de formato `key_secured` es una constante de la app
  (no una credencial de usuario) y vive en `RoVPN.py` como
  `CATALOG_PASSWORD`, igual que las contraseñas de formato de los demás
  proveedores.
- `nq0` compara `Version` con la preferencia `update` (por defecto
  `0.0`); si la remota es mayor, `tq0` importa el catálogo descifrado
  con `MainActivity.a0.b(...)` (ye1.b → Tink StreamingAead con clave
  maestra del Android Keystore → `profile.enc`), guarda la versión y
  muestra un diálogo con Version + Message.

### Valores `ED:`

Casi todos los campos de servidor y payload van con el prefijo `ED:` y
son **Base32 del texto plano UTF-8** (sin más cifrado): `ServerIP`,
`Cloudfront`, `Username`, `Password`, `Sni`, `ServerDNS`, `NameServer`,
`Payload`, `SquidProxy` y `setOpenVPN`. `RoVPN.py` incluye
`decoded(doc)` y la flag `--decoded` para imprimir el catálogo con esos
valores ya decodificados.

## Prueba viva 2026-11-13 (este script, --url, GET exacto)

HTTP 200, cuerpo 54.128 B, descifrado completo (10 segmentos GCM):
**Version 46.1**, Message ` Up`, **12 servidores** (todos libres, sin
marca premium) y **23 payloads** (Networks). El cuerpo vivo completo va
adjunto como `catalog_sample.b64` para `--self-test` / `--asset`.

Servidores (12): 1 OpenVPN directo, 5 Default (Cloudfront), 2 UDP
(Hysteria) y 3 SLOW (SSH + SlowDNS, con DNS y clave pública por
servidor). Hosts: `d1.rovpn.uk` (directo), `f1`–`f5.rovpn.uk`,
`home.rovpn.uk`, `u1`/`u2.rovpn.uk` (UDP) y 3 IPs SLOW. Todos con
puerto TCP 1194 salvo los SLOW (SSH 143) y los UDP (sin puerto TCP).
Payloads (23): 21 con texto HTTP (HTTP Proxy / Cloudfront, con
`[split]`, `[host]`, `[ua]`), 2 SlowDNS (SSH, sin payload, con DNS) y
1 Direct + 1 UDP Hysteria (sin payload). `setOpenVPN` trae la config
OpenVPN cliente completa (CA incluida); el servidor directo trae su
propia `setOpenVPN` por servidor.

## Archivos

### profile.json (legacy, importable) — `RoVPN_archivos.py`

`MainActivity.onCreate` lee `filesDir/profile.json` si existe:

1. Texto UTF-8 → Base64 propio (`aj2.c`, alfabeto estándar).
2. **XXTEA modificado** (`aj2.d`, delta `0x2E0BA747`, clave = primeros
   16 bytes UTF-8 de `MainDetail.b()` = `aZ%RU%itRMB^8&Ue`); el último
   word es la longitud del texto plano.
3. Renombres de claves: Servers `Name`→`ServerName`,
   `Flag`→`ServerFlag`, `SSLPort`→`OpenVPNSSLPort` **y** `SSHSSLPort`
   (ambos con el mismo valor), `ServerDNS` por defecto = `ServerIP`,
   `OvpnCertificate`→`setOpenVPN`, `AutoLogIn`/`MultiCert` bool→string;
   Networks `Name`→`PayloadName`, `Flag`→`PayloadFlag`,
   `Info`→`PayloadInfo`, `ServerDNS` por defecto `""`,
   `UseDefProxy` bool→string.
4. Importa con el mismo `a0.b(...)` que el catálogo y **borra el archivo**.

`RoVPN_archivos.py` decodifica (`decode()`) y también codifica
(`encode()`, `--encode`): toma un JSON con los nombres nuevos y produce
un `profile.json` válido (nombres antiguos, booleanos, XXTEA + Base64).
Round-trip verificado: sintético 5/5 y end-to-end con el catálogo vivo
(12 servidores, 23 payloads) cifrado como `profile.json` y vuelto a
abrir. **Pendiente: un `profile.json` real exportado del teléfono**
para la confirmación end-to-end.

### profile.enc (actual, NO abrible offline)

El catálogo importado se guarda como `profile.enc` en filesDir, cifrado
con Tink StreamingAead y clave maestra del Android Keystore
(`android-keystore://private_master_key`, AD =
`MY_SECURE_JSON_STREAM_V1`). **No se puede abrir offline.** El script
de archivos lo detecta (cabecera binaria Tink, primer byte 0x28) y lo
reporta como `PROFILE_ENC_KEYSTORE`.

Sin `.sks` en el manifiesto ni en el DEX.

## Esquemas de texto

**Ninguno propio.** Solo MAIN/LAUNCHER + Firebase messaging + servicios
VPN en el manifiesto; la única acción VIEW está dentro de `<queries>`,
no es una activity. Solo los estándares vmess://, vless://, ss:// y
trojan:// (import de v2rayNG).

URLs muertas / no usadas (sin llamadores desde Java):

- `https://iovpn.me/app/config/hg77hsushshss.php` (`MainDetail.a()`):
  GET → **HTTP 404** (página genérica de error, 4.182 B).
- `https://iovpn.me/app/v2ovpn/ping.json` (`MainDetail.c()`): GET →
  **HTTP 200, 480 B, 4 servidores TH** (g18/g7/g5/g4.drm.ac.th, puerto
  82). Es solo una lista de ping, no el catálogo.

## Archivos de este proveedor

- `RoVPN.py` — catálogo (`decode()` + `run()` + CLI `--url` /
  `--file` / `--asset` / `--stdin` / `--self-test`, `-o`, `--summary`,
  `--decoded`). Stdlib puro (AES-256-GCM en Python, PBKDF2, HKDF).
- `RoVPN_archivos.py` — `profile.json` (`decode()` + `encode()` +
  CLI `--file` / `--stdin` / `--encode` / `--self-test`, `-o`).
- `RoVPN.png` — ícono 512×512 (adaptativo xxxhdpi fg+bg compuesto;
  el XAPK no trae `icon.png`).
- `catalog_sample.b64` — cuerpo vivo cifrado (54.128 B, Version 46.1)
  para `--self-test` / `--asset`.
- `work/` — DEX, jadx, cadenas deobfuscadas, scripts de verificación
  (`decrypt_catalog.py`, `verify_pure.py`, `ping_live.json`).

## Pendiente

- Un `profile.json` real exportado del teléfono para la confirmación
  end-to-end del decodificador legacy.
- Si el proveedor rota `key_secured` o cambia el endpoint, el script
  dejará de abrir el catálogo vivo y lo reportará como
  `LIVE_DECRYPT_FAILED` / `DOWNLOAD_FAILED`, sin inventar servidores.
- `MainDetail.a()` (config antigua) y `MainDetail.c()` (ping) no tienen
  llamadores desde Java; si una versión futura los usa, el catálogo
  podría moverse a esa URL.
