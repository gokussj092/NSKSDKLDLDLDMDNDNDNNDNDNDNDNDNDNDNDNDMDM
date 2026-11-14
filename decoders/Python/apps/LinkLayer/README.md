# LinkLayer VPN — catálogo + archivos .lnk (VER6)

App: **LinkLayer VPN**, `com.newtoolsworks.linklayer`, versión **3.11.2** (versionCode 93),
minSdk 21. Versión de Google Play (actualizada 31 ago 2026), descargada de APKPure
(XAPK, SHA-256 `00ee9552d2de9e53d87ca9fa2a702b6bf754503c61cf108dc5af9fe894169642`).

## Cobertura previa en el repo SP-DECODE

El repo **ya cubría LinkLayer como formato de archivo** (`decoders/Python/linklayer.py`,
VER6, verificado contra un exportado real autorizado de 3.11.2 (93)). Lo que faltaba
era el **catálogo en vivo** de esta versión: este trabajo lo verifica y lo entrega.

- `analysis/` del repo: no hay carpeta de catálogo para LinkLayer (solo el decoder
  de archivos). El expediente VER6 está en `docs/LINKLAYER_VER6_INVESTIGATION_HANDOFF.md`.
- El decodificador de archivos de este paquete (`LinkLayer_archivos.py`) es el mismo
  método VER6 del repo, verificado en ESTE APK (constantes IV y XOR_SALT presentes
  en `libgojni.so`) y con salida idéntica al decoder del repo en pruebas sintéticas.

## Catálogo (gratuito) — VERIFICADO EN VIVO

**URL:** `https://linklayer.newtoolsworks.com/free.php`

**Petición exacta (como la app):** `GET` simple, sin parámetros, sin autenticación.
La app usa `net/http.(*Client).Get` del cliente por defecto de Go
(`User-Agent: Go-http-client/1.1`). El servidor responde igual con cualquier UA
(verificado con Go-UA y Dalvik-UA: mismo cuerpo, mismo SHA-256).

**Cifrado:** cuerpo = una línea Base64 estándar → blob OpenSSL `Salted__`
(8 B magic + 8 B salt + ciphertext) → `EVP_BytesToKey` con MD5 (1 iteración)
→ **AES-256-CBC, PKCS#7** → JSON. Es el `aes256.Decrypt` de
`github.com/mervick/aes-everywhere` (llamado en
`configuration.GetUpdateFreeListServers`, libgojni.so).

**Contraseña del formato:** se construye en tiempo de ejecución en
`configuration.init` (Go): `FormatInt(98548)` + `FormatInt(63245)` +
`"8oMkh2bs3pZcJL1XAb"` + `FormatInt(84277)` =

`98548632458oMkh2bs3pZcJL1XAb84277`

Es una constante del formato del catálogo (como las claves de otros proveedores),
no una credencial de usuario.

**Resultado en vivo (2026-11-14, verificado 3 veces, cuerpo determinista):**

| Campo | Valor |
|---|---|
| version | `v3.1- IPV6` |
| username / password | `free` / `free` |
| expiration | 0 |
| FreeLocationIndex | 0 |
| Ubicaciones gratuitas | **3**: USA 1, USA 2, Amsterdam 1 |
| Payloads | **0** — el catálogo no trae sección de payloads |

Cada ubicación trae: `hostHTTPTLS`, `hostip4`, `hostip6`, `sslPorts` y `httpPorts`
(`443,123,3128,80,8888,110,8080,53,5300`), `wsDomain`, `pubkey` (hex 64),
`domain`, `serverUDP`, `obfsUDP`, `httpdualSelect` y `httpdual` (3 opciones:
CDN 1 / Direct / Direct6). Las opciones de conexión son `httpdual`, no payloads.

- USA 1: `us1link.q-turbo.com` (208.87.243.119 / 2604:6600::27a)
- USA 2: `us2link.q-turbo.com` (108.181.2.147 / 2604:6600::27e)
- Amsterdam 1: `ams1link.q-turbo.com` (86.54.28.203 / 2a01:e940:0:2c3::2)

Cuerpo en vivo: 2.944 B Base64, SHA-256
`cf2d8172f0d377e547251369dc672f72b8e283abfadff7f3beb7409d13bd669b`
(guardado en `catalog_sample.b64`).

El catálogo incluido en el APK (`assets/flayer.dat`, incluido aquí) usa el MISMO
método y contraseña; solo cambian los hosts (`*.ntwtunnel.com` en vez de
`*.q-turbo.com`) y los `wsDomain` (`api1.q-turbo.com` etc.).

## Archivos

| Archivo | Descripción |
|---|---|
| `LinkLayer.py` | Catálogo: `decode()` + `run()` + CLI `--url/--file/--asset/--self-test`. Solo stdlib (AES puro en el script, verificado contra PyCryptodome). |
| `LinkLayer_archivos.py` | Archivos `.lnk` VER6: `decode()` + CLI + `--self-test`. Requiere PyCryptodome (`pip install pycryptodome`). |
| `LinkLayer.png` | Icono 512×512 (del XAPK). |
| `flayer.dat` | Catálogo incluido en el APK (v3.1, 3 ubicaciones, hosts ntwtunnel.com). Sirve para `--asset` y `--self-test`. |
| `catalog_sample.b64` | Cuerpo vivo de free.php (2026-11-14), para `--file` y `--self-test`. |
| `README.md` | Este archivo. |

```sh
python3 LinkLayer.py --url --summary
python3 LinkLayer.py --asset --summary
python3 LinkLayer.py --self-test            # 6/6 OK
python3 LinkLayer_archivos.py perfil.lnk
python3 LinkLayer_archivos.py --self-test   # 29/29 OK (round-trip sintetico VER6)
```

## Archivos de configuración (.lnk VER6)

- Importación: `ACTION_VIEW`, `mimeType application/octet-stream`, esquemas
  `file`/`content` con `pathPattern .*\.lnk` (ImportActivity). No hay `.sks`.
- Capas: `VER6 | Blowfish-CFB64 | AES-CFB128 | Salsa20 | CAST5-CFB64 |
  PBKDF2-SHA1 (32 iters, XOR 1500 B) | AES-CFB128` → Go gob `NativeConfig`
  (25 campos raíz, 60 hojas). Sin MAC.
- Constantes verificadas en este APK: IV `a7734f9c12ac1b01a415f2c1fc78e66b`
  (libgojni.so 0x24f2260), XOR_SALT `sH3CIVoF#rWLtJo6` (0x4691bc).
- **Pendiente:** confirmación de extremo a extremo con un `.lnk` real exportado
  desde un teléfono (el decoder está verificado contra el exportado real del
  repo y por round-trip sintético, no con un archivo de esta sesión).

## Esquemas URI de texto

**Ninguno propio.** No hay `linklayer://` ni otro esquema en el manifest ni en
el DEX (solo `http(s)://` estándar y `resource://`/`rtsp://` del sistema).
La única entrada es el archivo `.lnk`.

## Otros endpoints (no son el catálogo)

| Endpoint | Resultado |
|---|---|
| `GET https://linklayer.newtoolsworks.com/getInfo.php` | 200, JSON plano `{"time":"1 Day"}` (sin cifrado; `GetInfoFree` lo lee con `json.Decode`). |
| `GET https://linklayer.newtoolsworks.com/getCreds.php` | 403 vacío (necesita autenticación; credenciales de pago). |
| `GET http://version.newtoolsworks.com/version.php?apk=linklayer` | 200, blob `Salted__` (128 B) que **NO** abre con la contraseña del catálogo libre ni con las otras dos contraseñas del formato encontradas (`110NDsFA5mNe3y1qLj6h7B956`, `16383`); es la comprobación de versión, no el catálogo. Pendiente no bloqueante. |
| `https://linklayer.newtoolsworks.com/free.php` | El catálogo (ver arriba). |
| `https://misc.newtoolsworks.com/linklayer/dump1.php` | Endpoint presente en el binario; no probado (no es el catálogo). |

## Otros assets

- `assets/data.bin` (2.432 B, `Salted__`): **NO es el catálogo.** Descifra con
  la contraseña `16383` (otra constante del formato, en `androidclient.init`)
  y contiene un gob `RegistroV2` (clases/firmas para el comprobador
  anti-manipulación `(*checker).parseAssets`), no servidores. No se incluye
  como catálogo; documentado aquí para no confundirlo.
- `assets/flayer.dat` (2.968 B): el catálogo incluido (ver arriba).

## Librerías nativas (todas en `config.arm64_v8a.apk`; la base no tiene .so)

`libc++_shared.so`, `libdnstt-client.so`, `libgojni.so` (39.613.624 B, Go 1.25.0),
`libltun.so`, `libpl_droidsonroids_gif.so`, `libsshdnstt-client.so`,
`libudp-client.so`. El catálogo y el formato VER6 viven en `libgojni.so`
(paquete Go `newtools/linklayer/androidclient/configuration`).

## Qué queda pendiente

1. Un `.lnk` real exportado desde un teléfono para la confirmación de extremo
   a extremo del decoder VER6 (el método está verificado; falta la muestra).
2. La contraseña del blob de `version.php` (comprobación de versión; no afecta
   al catálogo).
3. `getCreds.php` / catálogo de pago: requiere credenciales de cuenta; no
   probado (el catálogo gratuito está completo).
4. `dump1.php`: sin probar; no es el catálogo gratuito.
