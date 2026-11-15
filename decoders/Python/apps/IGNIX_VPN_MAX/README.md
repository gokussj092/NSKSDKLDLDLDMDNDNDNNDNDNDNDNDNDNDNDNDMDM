# IGNIX VPN MAX — catálogo y archivos (SP-DECODE)

- **Paquete:** `http.ignixmax.vpn`
- **Versión analizada:** 44 / versionCode 44, minSdk 24 — **la versión pública
  en Google Play** (actualizada el 11 nov 2026; APK descargado de APKPure
  porque APKMirror no lo tenía, y verificado contra Play: es exactamente
  la 44).
- **Desarrollador:** Prominex (misma familia que JyFast VPN Ultra).
- **Cobertura en SP-DECODE:** **ninguna**. No hay carpeta IGNIX en
  `decoders/Python/apps/` (86 carpetas revisadas, rama
  `feat/nuevas-integraciones`) ni entrada `ignix` en `decoders.json`.
  JyFast VPN Ultra es OTRA app (`http.jyfast.vpnultra`) y su método NO
  aplica aquí: su catálogo era abierto; el de IGNIX exige autenticación
  de dispositivo.
- **Estado general: CATÁLOGO BLOQUEADO POR AUTENTICACIÓN DE DISPOSITIVO.**
  El método de transporte está identificado y verificado en vivo, pero el
  catálogo gratuito no se puede descargar sin un `server_token` de un
  dispositivo registrado, y el cifrado del catálogo aún no está
  identificado. Nada de esto se inventa: el script lo reporta como tal.

## Método del catálogo (transporte, verificado en vivo)

La app es SCKIT VMP (Prominex): la lógica de actualización vive en
`libprominexVMP+.so` (arm64, 1 048 152 B) + el asset `prominx-vmp+.vmp`
(210 262 B). Todas las cadenas del VMP se recuperaron por emulación
Unicorn (`work/ignix_vmp_strings.py`, adaptado del de JyFast):
**7 572 cadenas** en `work/all-strings.json`.

Endpoints (host `accesos.ignix-vpn.site`, todo HTTPS):

| Uso | Método + ruta |
|---|---|
| Catálogo gratuito | `GET /updateapk/ignix_update.php` |
| Catálogo VIP | `GET /vip/vip_catalog.php` |
| Challenge (nonce) | `GET /updateapk/ignix_challenge.php` |
| Registro de dispositivo | `POST /updateapk/ignix_register.php` |
| Estado premium | `GET /vip/sync.php` |
| Registro premium | `POST /updateapk/ignix_register.php` (mismo) |
| Verificación Google Play | `POST /vip/google_verify.php` |

Cabeceras exactas (User-Agent `IGNIX-VPN`):
- `X-IGNIX-SIG`: SHA-1 del certificado firmante del APK =
  `05856dee81c2ffcbbbeb100d5e2cc0884a848be5` (extraído del bloque de
  firma v2 del APK; confirmado por la cadena VMP id 446, en mayúsculas).
  Sin ella: `403 {"error":"firma invalida"}`.
- `X-IGNIX-AUTH`: `server_token` del dispositivo (SharedPreferences
  `ignix_device_auth_v2`: `device_id`, `device_secret`, `server_token`).
  Sin él, el catálogo responde `401 {"error":"no autorizado"}` aunque la
  firma sea correcta.

Flujo: challenge (solo firma) → registro del dispositivo → catálogo con
firma + token. El VIP además puede activarse con un token de
distribuidor (`Su token es: … envíaselo a su distribuidor`,
`token_no_existe`, `token_invalido`) o compra Google Play (`google_auth`).

## Prueba en vivo (2026-11-13, script `IGNIX_VPN_MAX.py --self-test`)

| Comprobación | Resultado |
|---|---|
| `ignix_challenge.php` con firma | **200** `{"ok":true,"nonce":"<32 hex>","ts":<unix>}` |
| `ignix_update.php` con firma, sin token | **401** `{"error":"no autorizado"}` |
| `ignix_update.php` sin firma | **403** `{"error":"firma invalida"}` |
| `vip_catalog.php` con firma, sin token | **401** `{"error":"desconocido"}` |
| `sync.php` con solo firma | **200** `{"premium":false,"reason":"desconocido","premium_until":0}` |
| `ignix_register.php` (todas las variantes) | **400** `{"error":"bad request"}` |
| Catálogo descargado | **NO** — versión, servidores y payloads **sin determinar** |

`--self-test`: 5/5 PASS (capa de auth). La ejecución completa
(`--device-id …`) termina con exit 2 y `error: no autorizado`.

## Por qué el registro no se pudo completar

Se probaron 20+ variantes de `ignix_register.php`: GET/POST, JSON/form/
query, `device_id`/`hwid`/`token`, `nonce`+`ts` del challenge, firmas
HMAC-SHA256 (clave = SHA-1 del firmante en hex y en bytes; mensaje
`nonce+device_id` y `device_id+nonce`), SHA-256 simple, `device_secret`
generado por el cliente y cabecera `X-IGNIX-AUTH`. Todas → 400.

La petición exacta vive dentro del bytecode VMP (`ConfigUpdate`,
clase 385). Ejecutarla requiere `registerClass`, que el runtime
rechaza con `Native entry does not belong to the runtime RX mapping`
cuando se invoca fuera de su mapeo RX, y su tarea Rust de fondo
(`pthread_create` → rutina `0xd8e78`) aborta en emulación. El cifrado
del catálogo (contraseña/alfabeto) también vive en el VMP: no está en
las 7 572 cadenas ni en el Java descompilado, así que no se puede
adivinar sin una respuesta autenticada. El script NO aplica el método
JyFast (`JyFastv1c2` / alfabeto `!?-=∆×÷…`): es de otra app y no hay
evidencia de que IGNIX lo comparta.

## Archivos de configuración

**La app no tiene formato propio importable.** El manifiesto no declara
ningún `intent-filter` de `ACTION_VIEW`/`ACTION_GET_CONTENT` para
archivos, no hay extensión propia (`.ignix`, `.sks`, etc.) ni esquema
URI propio (solo `https` para Custom Tabs). Lo que la app guarda en su
`filesDir` es el catálogo ya descifrado:
- `Config.json` (gratuito) y `ConfigPremium.json` (VIP), JSON en claro.
`IGNIX_VPN_MAX_archivos.py` lee esos archivos y resume versión /
servidores / payloads. Verificación: `--self-test` OK con un
`Config.json` sintético (forma Prominex/JyFast) y con un cuerpo cifrado
(reportado como pendiente, no inventado). **Falta una muestra real**
(`Config.json` extraído de un teléfono) para confirmar la forma exacta
del catálogo de IGNIX.

## Textos / enlaces

**No.** Sin esquema URI propio en el manifiesto ni en el código.
Solo los estándar (vmess/vless/ss/trojan), que ya cubre SP-DECODE.

## Entregables

| Archivo | SHA-256 |
|---|---|
| `IGNIX_VPN_MAX.py` | `34408a15bf286bcf5a0879adc7c80d21f80934018facf9b5c30a085d790ae906` |
| `IGNIX_VPN_MAX_archivos.py` | `5ee1cd18fc10df7045857d20b6c14db0b31df66c6bc3f856642223db39186f64` |
| `IGNIX_VPN_MAX.png` (512×512) | `44a1934b5612efb111a6a96285a36ade770339ece5f8ee1133928b67d1a7270c` |
| `README.md` | (este archivo) |

- `IGNIX_VPN_MAX.py`: stdlib puro. `decode()` + `run()` + CLI `--url`
  / `--vip` / `--token` / `--device-id` / `--raw-out` / `--self-test`.
  Sin token llega hasta el 401 y lo reporta; con `--token <server_token>`
  intenta la descarga real. `decode()` devuelve `CIPHER_PENDING` (con
  SHA-256 del cuerpo) si el cuerpo no es JSON: no inventa servidores.
- `IGNIX_VPN_MAX.png`: icono lanzador adaptativo `max_ico`
  (foreground + background `res/mipmap-xxxhdpi-v4/`, 432×432) compuesto
  y escalado a 512×512. El XAPK no traía `icon.png`.
- Icono verificado visualmente (lobo neón + «IGNIX VPN MAX»).

## Qué queda pendiente

1. **Un dispositivo registrado (o su `server_token`)**: con un token
   válido, `IGNIX_VPN_MAX.py --token <token>` descarga el catálogo y el
   cifrado se puede identificar a partir de la respuesta real.
2. **El formato exacto de `ignix_register.php`**: solo ejecutando el
   VMP (o decodificando el asset `.vmp`) se obtiene. Sin eso no hay
   registro desde cero.
3. **El cifrado del catálogo**: pendiente de (1).
4. **Muestra real de `Config.json`/`ConfigPremium.json`** de un teléfono
   para confirmar la forma del catálogo y validar el lector de archivos
   de extremo a extremo.
5. **Versión / servidores libres / payloads**: sin determinar hasta (1).

## Evidencia (`work/`)

- `all-strings.json` (7 572 cadenas VMP), `all-ids.txt`, `dex-strings.txt`
- `ignix_vmp_strings.py` (+ `arm64_function.py`, `elf_inspect.py`,
  `jyfast_vmp_strings.py` de referencia), `jni_onload.txt`, `setup-test.log`
- `probe_endpoints.py`, `probe_auth.py`, `probe_auth2.py`,
  `probe_register.py`, `probe_register2.py`, `probe_register3.py` y sus
  `.bin` de respuesta (`probe-*.bin`, `auth-*.bin`, `reg-*.bin`)
- `signer-cert.der` / `cert.der` (certificado firmante; SHA-1
  `05856dee81c2ffcbbbeb100d5e2cc0884a848be5`, SHA-256
  `159be61c877cbd1d95b8a1049089b5a075fdfbe166ad1f5823c9ec3759b3bc1a`,
  CN=felix, O=prominex, L=El Alto, La Paz, BO)
- `live-catalog-response.bin` (respuesta 401 en vivo)
- `regclass.log`, `regclass2.log`, `regclass3.log` (intentos VMP)

## APK de referencia

- XAPK: `~/workspace/browser_downloads/sess-3403840373/` (APKPure).
- Extraído en `apk/`: base `http.ignixmax.vpn.apk` (24 814 637 B) +
  `config.arm64_v8a.apk` (28 140 907 B, aquí viven las 14 librerías
  nativas, incl. `libprominexVMP+.so`) + `config.en/fr/hdpi.apk`.
- `assets/config/config.json` = `{}` (stub). `assets/prominx-vmp+.vmp`
  (210 262 B). `assets/flags/` (banderas de países).
