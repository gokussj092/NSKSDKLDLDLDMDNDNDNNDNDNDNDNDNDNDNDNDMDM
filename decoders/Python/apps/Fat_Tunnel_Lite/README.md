# Fat Tunnel Lite (vpn.jx.strongudp, Fat V1.12) — catálogo, archivos .fat y esquemas de texto

App: **Fat Tunnel Lite**, paquete `vpn.jx.strongudp`, versionCode **12**,
versionName `Fat V1.12`, minSdk 23, targetSdk 36. APK analizado:
`apk/base.apk` (30 MB), SHA-256
`f7ee5c42dc005d228b22a49a1c0527ccf9713f0aa51cdf3381452973228a7764`.
Fecha de trabajo: 2026-11-13. Alcance: **catálogo + archivos .fat +
esquemas de texto**, desde cero — el repo SP-DECODE (rama
`feat/nuevas-integraciones`) no tiene cobertura de Fat Tunnel Lite
(86 carpetas de apps, ninguna Fat; la referencia más cercana es
HX Tunnel VPN, misma familia de catálogo pero con XXTEA y otra URL).
No se modificó el repo SP-DECODE ni se subió nada a Git. No se guardan
ni se imprimen en este documento valores descifrados, contraseñas,
claves de usuario ni datos sensibles: solo recuentos, hashes y
estructura.

## Método exacto del catálogo

### Descarga

- **Endpoint activo:** `https://strongteam.co/api/fattunnel/` (GET).
  Es una URL fija sin parámetros, sin token de ruta.
- **Dónde vive la URL en el APK:** `Hometab$configUpdate$1` llama
  `Libv2ray.cu(version)`. `AndroidLibXrayLite.CU` (0x1016880, en
  `libgojni.so`, binario Go 1.24.3 de
  `github.com/2dust/AndroidLibXrayLite`) construye
  `http.NewRequestWithContext(ctx, "GET",
  "https://strongteam.co/api/fattunnel/", nil)` — la URL base está en
  `.rodata` 0x36c9f2 (36 caracteres) —, pone exactamente una cabecera,
  `User-Agent: Fat Tunnel Lite` (clave en `.rodata` 0x3445a3, valor en
  0x349d6a), y llama `http.Client.Do`. `Libv2ray.gfc()` devuelve la
  misma configuración fresca; HomeFragment la guarda en la preferencia
  `"KidConfig7"`.
- **Petición replicada:** GET, con la única cabecera
  `User-Agent: Fat Tunnel Lite` (el script añade además
  `Accept-Encoding: identity` y `Connection: keep-alive`; ver la
  incidencia de red abajo). **Sin User-Agent el endpoint responde 404**
  (verificado); con él, 200 y el cuerpo completo en un solo GET.
- **Sin autenticación, token de sesión, firma ni parámetros.**

### Descifrado de la respuesta

`CU` pasa el cuerpo a `AndroidLibXrayLite.decrypt` (0x1013cc0), lo
parsea como JSON y compara versiones con `compareVersion`:

1. **Base64 estándar** del cuerpo completo.
2. Blob con layout `salt[0:16] || nonce[16:28] || ciphertext[28:-16] ||
   tag[-16:]`.
3. **Argon2id** (time=3, memory=8192 KiB, parallelism=1, keyLen=32,
   versión 0x13) con la contraseña de formato de la app y
   salt = `blob[0:16]` → clave AES de 32 bytes.
4. **AES-256-GCM** con nonce = `blob[16:28]`, AAD = salt; el tag GCM
   autentica el cuerpo (a diferencia de los catálogos XXTEA de la
   familia, aquí un cuerpo truncado o corrupto **no** abre: el tag
   falla).
5. Resultado: **JSON UTF-8 completo**, sin filtrar campos.

Dos contraseñas de formato (constantes de la app, no credenciales de
usuario; `decrypt` usa la actual, `DO` la legacy — ambas construidas
desde `.rodata` con los últimos bytes por inmediato):
`decrypt`/`Encrypt`/`parseConfig` usan la actual;
`DO` (0x1014610, la que Java llama vía `Libv2ray.do_` para el asset
incrustado) usa la legacy. `decode()` prueba la actual primero y luego
la legacy, igual que `ConfigFileParser` (parseConfig, luego DO).

El asset incrustado `assets/configfile.json` es el mismo formato con
la contraseña legacy. El script lo lee con `--apks`.

### Flujo en la app

- Al arrancar, `HomeFragment` lee `assets/configfile.json` (o el valor
  guardado `"KidConfig7"`) y lo pasa por `Hometab.Companion.a` =
  `Libv2ray.do_` (contraseña legacy).
- Al actualizar, `Hometab$configUpdate$1` llama `Libv2ray.cu(version)`;
  si hay versión nueva, toma `Libv2ray.getVerNotes("Version" /
  "ReleaseNotes")` y `Libv2ray.gfc()` y guarda el resultado en
  `"KidConfig7"`.
- Las cadenas de la app **no** están cifradas con LSParanoid: en este
  DEX no existe clase `Deobfuscator` ni LSParanoid; las URLs y
  constantes viven en texto plano en `.rodata` de `libgojni.so`.
  El descifrado del catálogo vive en código nativo Go (`libgojni.so`,
  30 MB), con puentes JNI Java `libv2ray.Libv2ray.*`.

### Criptografía en Python estándar

Argon2id (RFC 9106) y AES-256-GCM están implementados en el script
con solo la biblioteca estándar (`hashlib.blake2b` + la ronda BlaMka).
Se verificaron contra `argon2-cffi` / `cryptography`, el vector de
prueba Argon2id de RFC 9106, un vector NIST AES-GCM, el asset
incrustado y una descarga en vivo. Un descifrado tarda ~15-20 s en
esta máquina (Argon2id domina); ese es el coste del formato, no de
la red. `--self-test` 5/5 en ambos scripts.

## Prueba real (no simulada) — 2026-11-13

Descarga con el script entregado contra el endpoint real y descifrado
con el mismo algoritmo. Solo recuentos; el JSON completo de prueba no
se guardó (los archivos de respuesta descargados se borraron tras
verificar).

| Fuente | Versión | Servidores | Payloads (Networks) | JSON (bytes) | Cifrado (bytes) |
|---|---|---|---|---|---|
| `assets/configfile.json` del APK (`--apks`) | 1.01 | 1 | 156 | 86655 | 115600 (Base64) |
| GET oficial (`--url --summary`) | **2.881** | **16** | **217** | 175428 | 233964 |

- Secciones en ambos documentos: `Version`, `ReleaseNotes`,
  `Telegram`, `WhatsApp`, `Facebook`, `DefOVPNUser`, `DefOVPNPass`,
  `HysteriaUser`, `HysteriaOBFS`, `DefaultOVPNCert`, `isTimerOn`,
  `timetoadd`, `Servers`, `Networks`.
- Campos de cada servidor: `Name`, `Flag`, `ServerIPHost`,
  `ServerType`, `ServerProtocol`, `OpenVPNTCPPort`, `OpenVPNUdpPort`,
  `SSH_Port`, `SSLPort`, `isdefUser`, `OVPNUser`, `OVPNPass`,
  `UDP_obfs`, `UDP_user`, `Default_cert`, `CustomCertificate`,
  `SlowDNSHost`, `SlowDNSKey`, `V2rayProtocol`, `V2rayUUID`,
  `V2rayPath`, `V2rayProto`, `H2pass`, `ServerInfo`. Campos de cada
  payload (Networks): `Name`, `Info`, `Payload`, `ProxyPort`, `SNI`,
  `DefaultProxy`, `CustomProxy`, `V2rayConfig`, `TunnelType`,
  `BugDNS`, `URI`, `V2rayAddress`, `V2rayPort`, `V2rayNetwork`,
  `Route`, `V2rayHost`, `V2ray_is_SNI`, `V2raySNI`, `V2rayServerNeed`,
  `Insecure`. Estructura validada por el script; no se listan valores.
- El `run()` offline sobre la respuesta remota guardada devuelve el
  mismo documento (versión 2.881, 16 servidores, 217 payloads);
  `run()` con entrada inválida devuelve `None`.

### Incidencia de red (importante para reproducir la descarga)

La respuesta es `Transfer-Encoding: chunked`, sin `Content-Length`,
servidor Cloudflare. El servidor **ignora `Range`** (responde 200 con
el cuerpo completo), así que no hay reanudación por rangos. Lo que sí
importa es la cabecera `Connection`:

- `urllib.request` añade `Connection: close` por defecto: con ella, la
  descarga se corta a mitad del cuerpo **siempre** (0/7 completas;
  parciales de 64–214 KiB, punto de corte variable).
- Sin cabecera `Connection`, o con `Connection: keep-alive`, el cuerpo
  completo llega **siempre** (3/3 con `http.client` directo, 4/4 con
  curl, 3/3 con socket crudo).

Causa probable: con `Connection: close` el túnel del proxy de salida
se desmonta antes de que termine el cuerpo chunked. El script
entregado usa `http.client` directamente (nunca urllib) y envía
`Connection: keep-alive`; un read truncado se reintenta con un GET
nuevo (hasta 6 intentos), y el tag GCM de `decode()` es lo que prueba
que un cuerpo está completo. Verificado: `--url --summary` devuelve
2.881 / 16 / 217.

## Archivos .fat — flujo y clave

- **Formato:** texto Base64 (una línea) → Argon2id + AES-256-GCM
  (mismo layout que el catálogo) → JSON UTF-8 de **un perfil**
  (una entrada de `Networks`: `Name`, `TunnelType`, `Payload`, `SNI`,
  `V2rayConfig`, ...). Sin IV separado: salt y nonce viajan en el
  blob; el tag GCM autentica.
- **Importación** — `ConfigFileParser` (manifiesto: ACTION_VIEW,
  mimeType `application/x-fat` / `application/octet-stream`, esquema
  `content`, pathPattern `.*\.fat`): lee el archivo como texto (máx.
  2 MiB) → `Libv2ray.parseConfig(text)` (contraseña actual); si falla
  → `Hometab.Companion.a(text)` = `Libv2ray.do_` (contraseña legacy) →
  `new JSONObject(...)`, leyendo `"Name"` y `"TunnelType"`; guarda el
  texto original como `"ConfigFile"`. Si todo falla: `"invalid"`.
  `main.proxylibv2ray__ParseConfig` (0x1019f40) llama a `decrypt`.
- **Exportación** — `NetworkAdapter.u()`: `Libv2ray.encrypt(
  gson.toJson(network))` → archivo `"<nombre>.fat"` en Downloads,
  mime `application/x-fat`. `Encrypt` (0x1013a20) es el inverso de
  `decrypt` (misma contraseña actual, salt/nonce aleatorios).
- **Políticas:** no hay contraseñas, HWID ni bloqueo de operador en
  el formato `.fat` (las protecciones de otros túneles no existen
  aquí); el lector entregado devuelve todos los campos.
- **✅ Contraseñas y cifrado verificados (2026-11-13).** Ambas
  contraseñas y el layout se probaron contra payloads reales de la
  propia app en el mismo formato: el asset incrustado (legacy) y el
  catálogo remoto en vivo (actual). Además, `.fat` sintéticos
  construidos con las librerías de referencia (Argon2id + AES-GCM)
  hacen round-trip por el script: actual 5/5, legacy 5/5, JSON plano
  5/5 (`--self-test`).
  - **Pendiente:** un `.fat` real exportado por Fat Tunnel Lite
    1.12, solo para confirmar el extremo a extremo (el cifrado y las
    contraseñas ya están probados contra datos reales de la app).
- **`.sks`: no hay nada.** Ninguna referencia a `.sks` en el
  manifiesto, en las cadenas ni en el bytecode. No se construyó
  ningún decodificador `.sks`.

## Esquemas de texto/enlaces — ninguno propio en vivo

- **Manifiesto:** no hay ningún intent-filter con esquema propio de
  la app (no existe `fat://`). No se construyó
  `Fat_Tunnel_Lite_textos.py`.
- **`v2rayng://install-config` y `v2rayng://install-sub`:**
  `UrlSchemeActivity` los atiende (además de `ACTION_SEND`
  `text/plain`): URL-decodifica el parámetro `url` y lo pasa al
  parseador estándar de enlaces v2rayNG. Son los esquemas estándar
  de v2rayNG (enlaces vmess/vless/trojan/ss y suscripciones), formatos
  que SP-DECODE ya decodifica; no hay texto cifrado propio de Fat.
- **No hay lectura de portapapeles ni parseo de texto con prefijo
  propio.**

## Archivos entregados

- `Fat_Tunnel_Lite.py` — catálogo, solo stdlib. `decode()` + `run()`
  + CLI (`--url`, `--apks`, `--stdin`, archivo posicional,
  `-o/--output`, `--summary`, `--self-test`). SHA-256:
  `7e43070e67ec490d71baa38020df6349a864da8823bce9830b42a1804efc9f7b`.
  Uso: `python3 Fat_Tunnel_Lite.py --url --summary` (remoto),
  `python3 Fat_Tunnel_Lite.py --apks apk/base.apk --summary`
  (incrustado). Al guardar usa `O_EXCL` y modo `0600` y no
  sobrescribe.
- `Fat_Tunnel_Lite_archivos.py` — archivos `.fat`, solo stdlib.
  `decode()` + `run()` + CLI (archivo posicional, `--stdin`,
  `-o/--output`, `--summary`, `--self-test`). SHA-256:
  `db9487e324b407a15241fa17debbb6c2137031c1a1231177a64a1b789285336c`.
- `Fat_Tunnel_Lite.png` — icono original del APK:
  `ic_launcher_foreground.webp` xxxhdpi (432×432) compuesto sobre
  blanco y reescalado a 512×512 (LANCZOS), PNG. SHA-256:
  `935b733f1821a0b22d84a04e0a72ccb6a9e0d5621c32a92ad0bf887f50023da6`.
- `README.md` — este documento.
- `apk/base.apk` + splits — APK analizado (SHA-256 arriba);
  `split_config.arm64_v8a.apk` (librerías nativas),
  `split_config.es.apk`, `split_config.xhdpi.apk`.
- `jadx-out/` — decompilación jadx 1.5.3 (11.500 clases, 49 errores).
- `work/` — análisis: `all_strings.txt` (141.206 líneas),
  `disasm.py` (desensamblador AArch64 con Capstone),
  `gopclntab.py` (parser del pclntab de Go), `crypto_test.py`
  (Argon2id + AES-GCM puros verificados contra las librerías de
  referencia), `bundled-catalog.json` y `remote-catalog.json`
  (JSON descifrados de referencia, solo para verificación),
  `test-current.fat` / `test-legacy.fat` / `test-plain.fat`
  (sintéticos para el round-trip), `icon/` (webp originales).
- `libs/arm64-v8a/` — librerías nativas del split (entre ellas
  `libgojni.so`, 30 MB, Go 1.24.3, donde vive el descifrado del
  catálogo). No hay `libputils.so` en esta app.

## Contrato de salida

- Catálogo: `decode()` devuelve el JSON completo del catálogo como
  `dict` (secciones `Version`, `Servers`, `Networks`, ...); `run()`
  devuelve ese JSON como texto o `None` si la entrada no es un
  catálogo válido. `--summary` solo emite versión y recuentos, nunca
  valores descifrados.
- Archivos: `decode()` devuelve el JSON del perfil `.fat` como `dict`
  con todos sus campos; `run()` devuelve ese JSON como texto o `None`.
  `--summary` solo emite claves y recuento de campos.

## Pendientes

1. **Archivos .fat:** probar contra un `.fat` real exportado por Fat
   Tunnel Lite 1.12 (no existe ninguno en el repo ni en este
   workspace). El cifrado y ambas contraseñas ya están verificados
   contra datos reales de la app; el `.fat` real solo confirmaría el
   extremo a extremo.
2. El endpoint remoto cambia con frecuencia (1.01 incrustado → 2.881
   en vivo el 2026-11-13); el script no fusiona perfiles locales (eso
   lo hace la app en `CU`/`gfc`).
3. El descifrado puro en Python tarda ~15-20 s por documento
   (Argon2id, 8192 KiB × 3 pasadas); en el runtime de SP-DECODE
   conviene avisar al usuario o descifrar en segundo plano.
