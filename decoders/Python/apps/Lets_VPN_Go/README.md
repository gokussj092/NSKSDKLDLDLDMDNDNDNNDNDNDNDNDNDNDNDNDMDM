# Lets VPN Go (smith.vpn.ko.ni.pro, 1.7) — catálogo, archivos .js/.rj y textos letsvpngo://

App: **Lets VPN Go**, paquete `smith.vpn.ko.ni.pro`, versionName **1.7**,
versionCode **17**, minSdk 23, targetSdk 36. APK descargado de APKPure
(APKMirror no la tenía) como XAPK y extraído en `apk/`: base
`smith.vpn.ko.ni.pro.apk` (28.522.490 B) + `config.armeabi_v7a.apk`
(31.433.802 B, aquí viven **todas** las librerías nativas — esta app es
de **32 bits, armeabi-v7a solamente, sin arm64**) + `config.en.apk` +
`config.mdpi.apk`. Fecha de trabajo: 2026-11-13. Alcance: **catálogo +
archivos + textos**, desde cero — el repo SP-DECODE (rama
`feat/nuevas-integraciones`) no tiene cobertura de Lets VPN Go
(86 carpetas de apps, ninguna Lets; la familia más cercana es
RENZ/7NET: Xhypher Tunnel Pro y SevenNET VPN, mismo motor).
No se modificó el repo SP-DECODE ni se subió nada a Git. No se guardan
ni se imprimen en este documento valores descifrados, contraseñas,
claves de usuario ni datos sensibles: solo recuentos, hashes y
estructura.

## Método exacto del catálogo

### Descarga

- **Endpoint activo:** `https://raw.githubusercontent.com/TkMasterc/LetsVPN/refs/heads/main/README.md`
  (GET). Es una URL fija sin parámetros, sin token de ruta.
- **Dónde vive la URL en el APK:** las cadenas de la app están
  ofuscadas con un desofuscador propio estilo LSParanoid
  (`defpackage.ul`: tabla de 5 trozos, 35.454 caracteres, constantes
  de mezcla de semilla iguales a LSParanoid). Se resolvieron **1.760 /
  1.760 cadenas** con la herramienta de referencia
  `paranoid-deobfuscator` 3.0.2 (el puerto Python de LSParanoid de la
  tanda 2 **no** reproduce los resultados correctos; no usarlo). La
  URL aparece en `LetsVPNGoMain.N(Z)V` (línea 883): si `a0()` es
  cierto, la app hace `Volley.newRequestQueue(this).add(new
  StringRequest(url, listener, errorListener))` — un GET plano sin
  cabeceras propias ni autenticación. `a0()` solo comprueba que
  exista `/META-INF/XHYPHERT.RSA` o `/META-INF/BNDLTOOL.RSA` (firma
  del APK); no afecta al script.
- **Petición replicada:** GET plano, sin cabeceras propias ni auth,
  exactamente como el `StringRequest` de Volley. Verificado en vivo
  con `urllib` sin cabecera `User-Agent` personalizada: HTTP 200 y
  cuerpo byte a byte idéntico al descargado con curl.
- **Respuesta:** un único blob Base64 (357.401 B en vivo).
- **Qué hace la app con la respuesta** (`LetsVPNGoMain.i.onResponse`,
  línea 384): recorta espacios → `bc1.m` comprueba que sea Base64 →
  `hc1.a` descifra el sobre exterior (modo 0) → `d50.a` compara la
  `Version` del documento con la guardada (solo acepta versión
  **mayor**, comparación numérica por componentes) → `L()` guarda el
  texto **cifrado tal cual** en un zip dentro de `getFilesDir()`. La
  app guarda el catálogo cifrado y descifra cada campo en el momento
  de mostrarlo (`bc1.b` = modo 0, `bc1.c(ctx, str, 1)` = modo 1).

### Descifrado de la respuesta

Perfil `"letsvpngo"` de `decoders/Python/renz.py`, **verificado byte a
byte en `libovpn3.so` (armeabi-v7a) de este APK**: KEY_SEED en
`.rodata` 0x1ba9c4, IV en 0x1ba9e4, FIXED_SALT en 0x1ba9a4. Los métodos
nativos `RenzUtils.decrypt/encrypt` (Java
`renz.javacodez.vpn.utils.RenzUtils`) viven en `libovpn3.so`, que
también contiene los símbolos `threefishDecrypt` /
`threefishDecrypt1024`.

1. **Base64 estándar** del cuerpo completo.
2. **AES-128-CBC** (clave = SHA-256(KEY_SEED)[:16], IV fijo) con
   PKCS#7 → texto intermedio.
3. **XXTEA modificado** (delta 0x7A56D3E1, rondas 6 + 52/n, última
   palabra = longitud del texto plano) → **JSON UTF-8 completo**.
   Lets VPN Go **NO** aplica el paso "-2 por byte" (como
   xhypher/safetunnel/mhrtunnel).
4. Cada campo del JSON se descifra con su modo:

   | Modo | Campos | Cifrado |
   |---|---|---|
   | 0 | Name, Subname, OpenVPNTCPPort, OpenVPNSSLPort, CloudfrontDNS, flag, Obfs, CustomCert, Info, DNSResolver, TLSVersion, NSNameServer, PubKey, UUID, Squid, Port, UpMbps, DlMbps, RecvConnectionWindow | Igual que el sobre exterior (AES-128-CBC + XXTEA) |
   | 1 | ServerIPHost, SNIHost, Payload, PATH, V2RayHost, CustomV2RAYConfig | Threefish-256 (claves HKDF-SHA256 de KEY_SEED/FIXED_SALT; tweak t1 = índice de bloque × 192) → AES-128-CBC (clave HKDF16, IV fijo) |
   | 2 | Username, Password (global y por servidor) | Portador Unicode invisible (U+200B = bit 0, U+200C = bit 1, U+200D = relleno sin datos; intercambio de bits adyacentes, XOR 0x5A) → XXTEA (clave PBKDF2-HMAC-SHA256, 100.000 iteraciones, 32 B) → AES-256-CBC con IV = primeros 16 bytes del texto |

   `Version` y `Notes` van en claro. `Protocol`, `TunnelType`,
   `PayloadMode`, `EnableWS`, `AutoReplace`, `UseCustomCert`,
   `V2RayType`, `WSType`, `DNSMode`, `ReverseAddress`, `ReverseOnly`
   son valores simples en claro.
   El esquema de modos es el mismo de Xhypher Tunnel Pro
   (`codec.py`: SERVER_FIELDS / NETWORK_FIELDS / NESTED_FIELDS);
   aquí se confirmó campo por campo contra el catálogo en vivo
   (ver "Prueba real").

### Criptografía en Python estándar

AES-128/256-CBC, XXTEA modificado y Threefish-256 están
implementados en los scripts con solo la biblioteca estándar (sin
pycryptodome, a diferencia de `renz.py`). Se verificaron contra
`pycryptodome` y contra el propio `renz.py` como oráculo:
vector FIPS-197 AES-128, round-trip CBC 128/256, round-trip XXTEA
en 6 longitudes, round-trip Threefish-256 por bloque,
`renz_decrypt_main` abre lo que cifra `encode_main`,
`renz_decrypt_speciale` abre lo que cifra `encode_special`, y el
`decode_main` propio coincide byte a byte con `renz_decrypt_main`
sobre el catálogo en vivo (224.598 B). `--self-test` 36/36 en el
script de catálogo y 39/39 en el de archivos.
Un descifrado completo del catálogo en vivo tarda ~16 s en Python
puro (la expansión de clave AES se cachea; sin caché eran ~34 s);
`--self-test` tarda menos de 2 s.

## Prueba real (no simulada) — 2026-11-13

Descarga con el script entregado contra el endpoint real y descifrado
con el mismo algoritmo. Solo recuentos; el JSON descifrado completo
de referencia está en `work/catalog_live_decrypted_full.json` (solo
para verificación, no se distribuye).

| Fuente | Versión | Servidores | Payloads (Networks) | JSON (bytes) | Cifrado (bytes) |
|---|---|---|---|---|---|
| GET oficial (`--url`) | **654** | **43** | **197** | 224.598 | 357.401 |

- Secciones del documento: `Version`, `Servers`, `Networks`,
  `Username`, `Password`, `Notes`.
- Campos de cada servidor: `Name`, `ServerIPHost`, `Subname`,
  `OpenVPNTCPPort`, `OpenVPNSSLPort`, `Protocol`, `CloudfrontDNS`,
  `ServerHTTP`, `flag`, `Obfs`, `Username`, `Password`,
  `UseCustomCert`, `CustomCert`, `SlowDNS` (5 servidores),
  `V2Ray` (18 servidores). Campos de cada payload (Networks):
  `Name`, `SNIHost`, `Payload`, `Info`, `TunnelType`,
  `DNSServerHost`, `DNSResolver`, `AutoReplace`, `TLSVersion`,
  `EnableWS`, `V2Ray` (15 redes), `PayloadMode`, `ProxySettings`
  (197 redes), `UDPOptions` (17 redes). Estructura validada por el
  script; no se listan valores.
- **Verificación independiente:** el catálogo en vivo se descifró
  primero con el `renz.py` del repo (`work/validate_full.py`):
  **0 campos con problemas** en los 43 servidores y las 197 redes
  (modos 0/1/2 confirmados campo por campo). La salida del script
  entregado contiene todos esos valores idénticos y además conserva
  6 campos en claro que la validación de referencia no copiaba
  (`DNSMode`, `ReverseAddress`, `ReverseOnly`, `UseCustomV2RAYConfig`,
  `V2RayType`, `WSType`).
- El `run()` offline sobre el blob guardado devuelve el mismo
  documento (versión 654, 43 servidores, 197 payloads); `run()` con
  entrada inválida devuelve `None`.
- **Nota sobre los nombres de red:** algunos valores `Name` de
  Networks contienen en el propio texto plano una ristra de
  caracteres "ꠋ" (U+A80B) entre un prefijo y el sufijo real (por
  ejemplo `TkMaster⸙ꠋꠋ…ꠋVodaCom|Uɴʟɪᴍɪᴛᴇᴅ`). No es un error de
  descifrado: la longitud XXTEA (`out_len`) es igual a la longitud
  completa, así que el relleno forma parte del texto plano que guarda
  el catálogo. El script lo conserva tal cual, sin limpiarlo.
- El nombre del archivo remoto (`README.md`) no rota por mes: la URL
  es fija. La versión del catálogo es un número simple (`654`) y la
  app solo acepta versiones mayores que la guardada.

## Archivos .js/.rj y textos letsvpngo:// — flujo y clave

- **Archivos (`.js`, `.rj`)** — `LetsVPNGoMain.G`: la app acepta
  archivos que terminan en `.js` o `.rj` (¡no `.letsvpngo`!). Lee el
  archivo como texto, lo recorta, lo descifra con el sobre exterior
  (modo 0) y exige que su campo `Version` sea mayor que la versión
  guardada (`d50.a`); si pasa, guarda el texto cifrado tal cual como
  catálogo nuevo y reinicia la app. Es decir: **un archivo `.js`/`.rj`
  es el mismo blob Base64 del catálogo**. `Lets_VPN_Go_archivos.py`
  lo abre y devuelve el JSON con todos los campos descifrados.
- **Textos (`letsvpngo://`)** — `LetsVPNGoMain.e` onClick: el usuario
  pega un enlace `letsvpngo://…`; la app quita el prefijo, descifra
  el sobre exterior (modo 0) y obtiene un **perfil individual**
  (servidor + red) al que añade `isSetExpiry`, `Expiry`,
  `isPinEnabled`, `NetworkPinCode` y `Lock` (en claro dentro del
  perfil); luego lo vuelve a cifrar (modo 0) y lo copia al
  portapapeles como `letsvpngo://…`. `Lets_VPN_Go_archivos.py`
  abre el enlace (con o sin esquema) y devuelve el perfil con los
  campos descifrados y las protecciones tal cual.
- **✅ Verificado (2026-11-13).** `--self-test` 39/39 (perfil
  sintético `letsvpngo://` 2/2, archivo `.js` sintético, `run()`).
  Además, con datos reales de la app: el blob real del catálogo en
  vivo abierto como `.js` coincide exactamente con la salida de
  `Lets_VPN_Go.py --url`; y un enlace `letsvpngo://` construido con
  los registros reales (cifrados) del servidor 0 y la red 0 del
  catálogo en vivo recupera esos registros descifrados exactos, sin
  avisos.
  - **Pendiente:** un `.js`/`.rj` real o un `letsvpngo://` real
    exportado por Lets VPN Go 1.7 en el teléfono, solo para
    confirmar el extremo a extremo (el cifrado y los modos ya están
    probados contra datos reales de la app).
- **`.sks`: no hay nada.** Ninguna referencia a `.sks` en el
  manifiesto, en las cadenas ni en el bytecode. No se construyó
  ningún decodificador `.sks`.

## Esquemas de texto/enlaces

- **`letsvpngo://`** — esquema propio y funcional: enlace de perfil
  cifrado (modo 0), ver arriba. Es el único esquema propio de la
  app.
- **`v2rayng://install-config` y `v2rayng://install-sub`:** la app
  los atiende como fork de v2rayNG (enlaces vmess/vless/trojan/ss y
  suscripciones estándar), formatos que SP-DECODE ya decodifica; no
  hay texto cifrado propio.
- **Telegram `https://t.me/letsvpngo`:** solo un enlace al canal,
  no un formato de perfil.

## Archivos entregados

- `Lets_VPN_Go.py` — catálogo, solo stdlib. `decode()` + `run()` +
  CLI (`--url`, archivo posicional, `-o/--output`, `--self-test`).
  SHA-256:
  `771a902ecf58ada7fd33c29f0063ceb4fecda3d38d67ffb88410403c01ed34d0`.
  Uso: `python3 Lets_VPN_Go.py --url` (remoto),
  `python3 Lets_VPN_Go.py catalogo_guardado.md` (blob local),
  `python3 Lets_VPN_Go.py --self-test` (offline).
- `Lets_VPN_Go_archivos.py` — archivos `.js`/`.rj` y textos
  `letsvpngo://`, solo stdlib. `decode()` + `run()` + CLI (archivo
  posicional, `--text`, stdin, `-o/--output`, `--self-test`).
  SHA-256:
  `158b68944297cca5cb0ee572a52b5690adf66652e93832bb5c73331cedb13b71`.
  Uso: `python3 Lets_VPN_Go_archivos.py perfil.js`,
  `python3 Lets_VPN_Go_archivos.py "letsvpngo://...."`.
- `Lets_VPN_Go.png` — icono original del XAPK (`apk/icon.png`),
  512×512 RGBA, sin cambios. SHA-256:
  `0873e445de0976a89bb37ebdf845cec6decaecd6ef38a0792816f7d96eeac52f`.
- `README.md` — este documento.
- `apk/` — base + splits extraídos del XAPK, `icon.png`,
  `manifest.json`.
- `libs/` — las 10 librerías nativas de `config.armeabi_v7a.apk`
  (todas de 32 bits): `libdns.so` (Go), `libgojni.so` (Xray-core),
  `libhysteria2.so`, `libmmkv.so`, `libogkayouy.so` (Go 1.19.3,
  cliente/servidor del túnel), `libotensahorse.so`, `libovpn3.so`
  (aquí vive `RenzUtils` + Threefish; KEY_SEED 0x1ba9c4, IV
  0x1ba9e4, FIXED_SALT 0x1ba9a4 en `.rodata`), `libpdnsd.so`,
  `libtun2socks.so`, `libv2raysocks.so`. El base APK no tiene
  ninguna `.so`.
- `jadx-out/` — decompilación jadx 1.5.3 (15.682 archivos Java,
  68 errores, normales en apps ofuscadas). JRE Temurin 17 usado
  para jadx: `/tmp/jdk-17.0.21+9-jre` (no está en el PATH del
  sistema; `apt` quedó atascado en el proxy).
- `work/` — evidencia: `deob_strings.txt` (1.760 cadenas
  resueltas), `resolve_ul.py` (resolutor del ofuscador `ul`),
  `catalog_live.md` (blob en vivo, 357.401 B),
  `catalog_live_decrypted_full.json` (JSON descifrado de referencia),
  `catalog_live_mine.json` (salida del script entregado),
  `test_modes.py` (confirmación de modos por campo),
  `validate_full.py` (validación completa contra `renz.py`),
  `test_catalog.js` / `test_profile_link.txt` (muestras de prueba
  construidas con datos reales), `jadx.log`.

## Contrato de salida

- Catálogo: `decode()` devuelve el JSON completo del catálogo como
  `dict` (secciones `Version`, `Servers`, `Networks`, `Username`,
  `Password`, `Notes`); `run()` devuelve ese JSON como texto o
  `None` si la entrada no es un catálogo válido.
- Archivos/textos: `decode()` devuelve el JSON del perfil o del
  catálogo como `dict` con todos sus campos descifrados; `run()`
  devuelve ese JSON como texto o `None`. Los campos que no abren
  con ningún modo se dejan en claro y se avisan por stderr.

## Pendientes

1. **Archivos y textos:** probar contra un `.js`/`.rj` real o un
   `letsvpngo://` real exportado por Lets VPN Go 1.7 en el
   teléfono (no existe ninguno en el repo ni en este workspace).
   El cifrado y los tres modos ya están verificados contra datos
   reales de la app; la muestra real solo confirmaría el extremo
   a extremo.
2. El descifrado completo del catálogo en Python puro tarda ~16 s
   (Threefish + AES por campo); en el runtime de SP-DECODE conviene
   avisar al usuario o descifrar en segundo plano.
