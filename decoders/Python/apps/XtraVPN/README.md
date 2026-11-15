# XtraVPN 1.0.36 (com.xtravpn.dev) — catálogo y campos de servidor

Decodificador del catálogo de XtraVPN, versión 1.0.36 (versionCode 62,
minSdk 24), descargada de APKPure (APKMirror no la tenía) y verificada
contra Google Play: la versión pública en Play es 1.0.36 (actualizada
12 nov 2026). Sin cobertura previa en SP-DECODE (86 carpetas de
proveedores revisadas; no hay XtraVPN).

## Archivos

| Archivo | Descripción |
|---|---|
| `XtraVPN.py` | Decodificador del catálogo (stdlib puro, Python 3.10+). `decode()` + `run()` + CLI `--url` / `--file` / `--asset` / `--self-test`. |
| `config.json` | Asset `assets/config/config.json` del APK (3 612 bytes, cifrado), incluido para `--self-test` y `--asset`. |
| `XtraVPN.png` | Icono del XAPK, 512×512 RGBA. |
| `README.md` | Este archivo. |

No hay `XtraVPN_archivos.py`: el único formato de archivo de la app
es **.sks** (filtro `.*\.sks` en el manifest y en
ConfigImportFileActivity), y Pedro excluye los .sks. La app acepta
texto compartido (ACTION_SEND EXTRA_TEXT) vía ImportActivity, pero ese
texto es el mismo blob cifrado del catálogo que decodifica
`XtraVPN.py`, no un formato aparte. No hay esquema URI propio
(no existe `xtravpn://`); el manifest solo declara `file`/`content`
(para .sks), `https` (una entrada `<queries>`, no un deep link), `sms`
y `tel`.

## Método del catálogo

**La app no tiene URL pública de catálogo.** El listado de servidores
se descarga solo desde una URL por dispositivo ("custom code"):

1. `SharedPreferences "AppPreferences" → "customCode"`.
2. `Vj0.h(code, android_id)`: AES-128-ECB, clave = primeros 16 bytes
   del Android ID, datos = Base64. Si el resultado empieza por
   `https://`, esa es la URL. La constante de respaldo
   `"23605c1568999d3a"` son 12 bytes tras Base64 y no puede descifrar:
   es un camino muerto.
3. `Lv0.run()`: GET plano con HttpURLConnection, sin cabeceras propias,
   timeouts 5 000 ms; no-200 → `"Error on getting data: HTTP <código>"`.
4. El callback LAK descifra lo descargado con la clave B0 (el ID de
   AdMob, ver abajo) vía XXTEA, valida comparando el campo `Version`
   segmento a segmento contra el config actual y, si es más nuevo, lo
   guarda (aún cifrado) en `filesDir/Config.json`.

**Envoltorio exterior (LC7 / uW, igual para el asset y para el remoto):**
Base64 → XXTEA modificado (delta `0xF5D09E4D`), clave = bytes UTF-8 de
la clave truncados/rellenos a 16 bytes, palabras little-endian, última
palabra = longitud del texto plano → JSON. Dos claves:

- `"Pitingo2089"` — ServersActivity (hj caso 6). Abre el asset.
- `"ca-app-pub-1778627428199734/4229593543"` — XtravpnMainActivity
  (hj caso 17, el ID del banner de AdMob). Es la clave del camino
  remoto.

`--url` acepta la URL del custom code (o cualquier URL que sirva el
mismo envoltorio) y prueba B0 primero y luego `"Pitingo2089"`,
informando cuál abrió el config. Sin una URL de custom code no hay
nada en vivo que descargar.

## Campos de servidor (Sp0.l)

Tras abrir el JSON exterior, cada campo se descifra y luego pasa por
`XA.b`, un desplazamiento César de **-1 solo en letras**
(`XtravpnMainActivity.a == 1`, desplazamiento = 26 − 1 = 25):

| Campo | Método | Clave |
|---|---|---|
| ServerIP | Vj0.h: AES-128-ECB, clave = primeros 16 bytes, datos Base64 | r58 |
| ServerUser | uW.i: Base64 → XXTEA | r56 |
| Payload | K9.h | r55 |
| SNI | K9.h | r55 |
| udpserver | K9.h | r56 |
| udpobfs | K9.h | r57 |
| v2rayJson | K9.h | r58 |
| Slowchave, Nameserver, Slowdns, udpauth, udpbuffer, udpdown, udpup | texto plano | — |

Claves de campo (constantes de 20 caracteres construidas en `Lys.a`):

- r55 = `D7FoVFa7UrpkAuc03rQc` (Payload, SNI)
- r56 = `e6iQG0hiMfZWO8aOmLJY` (ServerUser, udpserver)
- r57 = `cNEi7mEOyQyxRX5A275J` (udpobfs; también abre el ServerPass del asset)
- r58 = `eXjaA5SFxj5vr4t1sjql` (ServerIP, v2rayJson)

**K9.h(clave, datos):** decodificación por pares con el alfabeto de
16 caracteres `:;<=>?!"#$%&'()*` (primer carácter = nibble alto,
segundo = nibble bajo) → texto Base64 → Base64 → AES-256-CBC, clave =
SHA-256 del hex EN MAYÚSCULAS de los bytes UTF-8 de la clave, IV = 16
bytes cero → UTF-8. (La cadena completa del alfabeto, de 27
caracteres, es Base64 de `Ojs8PT4/ISIjJCUmJygpKissLS4ve3x9fis9`; en los
datos solo aparecen sus primeros 16 caracteres.)

**ServerPass no lo lee la app.** El literal `ServerPass` no aparece en
`classes.dex`. La contraseña SSH se deriva en tiempo de ejecución con
`Sp0.g` (ver abajo). El valor del asset es un marcador que abre con
K9.h(r57) a un texto de prueba con emojis y se ignora.

## Contraseña SSH (Sp0.g, cambia cada hora UTC)

```
sshPass = SHA-256 hex (minúsculas) de
  ServerUser (ya con César) + AAAAMMDDHH (UTC) +
  "MiClaveSecreta2024XYZ" (Sp0.j) + slice1 + noise1 + slice2 +
  "ZyxClave9087Secreta\x00" (Sp0.k, 19 bytes con NUL final) +
  noise2 + slice3 + noise3
  → primeros 16 caracteres hex.
```

`slice1/2/3` son subcadenas del hex en minúsculas del SHA-256 del
certificado de firma del APK (QV.g), en los índices de firma; `noise1/2/3`
son las cadenas de ruido. Valores por defecto (`Ljt.b`, los que usa la
app hoy porque la sig-config remota no descifra): índices
(5,7,18,6,38,5), ruido (`k9Xm2P`, `Tz7nWq`, `Rb4vYj`). Para este APK el
SHA-256 del certificado (bloque de firma v2) es
`0724df38ff26b2d54bc9ffbe4de63a374b9080368af08f2b50fc02dd4cf58a62`,
así que los slices por defecto son `f38ff26`, `c9ffbe`, `368af`.
Existe un segundo camino en `Ld2.run` con índices ajustados
(start1+3, start2+5, start3+2) y ruido (`x9Km3R`, `Pq8nVw`, `Tz2jYb`);
`--sig adjusted` lo reproduce.

## Estado en vivo (verificado 2026-11-13 con este script)

- **Asset incluido:** abre con `Pitingo2089`: Version **1.0.0**, **1
  servidor** ("Tigo Panamá. Op-1", PA, ServerPort 80, SSLPort 443,
  isDirect). Sin sección de payloads: el payload vive dentro del
  campo Payload del servidor. `--self-test` 8/8 OK.
  - ServerIP → `unpkg.com` (un hostname, no una IP numérica).
  - ServerUser → `tipaop1`.
  - Payload → texto HTTP legible (`GET / HTTP/1.9[crlf]host:
    unpkg.com… OPTIONS… Expect: 200-continue… Proxy-Connection:
    Keep-Alive…`); el `HTTP/1.9` es literal del proveedor.
  - SNI → `abc.greenp.site`.
  - sshPass (hora UTC 2026-11-13 20:00) → `b00bba8b0c57be02`.
  - udpserver, udpobfs, v2rayJson: vacíos en el asset.
- **Sin URL de catálogo del proveedor:** no hay nada en vivo que
  descargar sin la URL del custom code de un dispositivo.
- **Sig-config remota (fracaso honesto):** `GET
  https://cdn.toolsp.site/05da6d93ed43e5ff/259bc7b35aa0` → HTTP 200,
  473 bytes, estable entre descargas y User-Agents (SHA-256
  `2313681f2ff7753d4b7d5e0865edda7ef70fefd0f3f664b2814d94e56b0c8362`),
  pero **no descifra** con la clave fija de la app
  `xF6qT4S41xonP9eAwQ` (padding PKCS#7 inválido con todas las
  derivaciones de clave probadas). La propia app lanzaría
  `config_error` y seguiría con los valores por defecto.
  `--sig-config` lo reporta así.
- **Feed de mensajes del admin (no es catálogo):** SMS_Updater descarga
  `https://bitbin.it/UJoIPP7n/raw` (GET plano) y lo parsea directamente
  como JSON `{SendMessage, MyMessage}`. El contenido servido hoy son
  5 520 bytes de texto ofuscado estilo K9, no JSON, así que la
  compilación actual tampoco podría parsearlo. Es un feed de mensajes
  del admin, no datos de servidores.

## Uso

```
python3 XtraVPN.py --asset                  # decodifica el config.json incluido
python3 XtraVPN.py --file config.json       # archivo local cifrado
python3 XtraVPN.py --url <URL-custom-code>  # URL del custom code del dispositivo
python3 XtraVPN.py --self-test              # 8 comprobaciones (asset + endpoints)
python3 XtraVPN.py --sig-config             # intenta descifrar la sig-config remota
python3 XtraVPN.py --ssh-pass tipaop1       # contraseña SSH para la hora UTC actual
python3 XtraVPN.py --ssh-pass tipaop1 --hour 2026111320
python3 XtraVPN.py --ssh-pass tipaop1 --sig adjusted
```

## Librerías nativas

El APK base no tiene `.so`; las 9 viven en `config.arm64_v8a.apk`:
`libgojni.so` (xray-core Go), `libxray.so`, `libfarikudp.so`,
`libdns.so`, `libdnstt.so`, `libpdnsd.so`, `libtun2socks.so`,
`libconscrypt_jni.so`, `libpl_droidsonroids_gif.so`. El catálogo es
Java puro; ninguna librería interviene en el descifrado del catálogo.

## Pendiente

- Un `Config.json` real descargado en un teléfono (config de
  custom code) o la URL descifrada del custom code, para confirmar
  el camino remoto (clave B0) de extremo a extremo.
- Un `.sks` real queda excluido por petición de Pedro.
- La sig-config remota hoy no descifra con la clave de 1.0.36: si el
  proveedor la vuelve a publicar con esa clave (o con una nueva
  versión de la app), los índices/ruido de firma podrían cambiar y
  con ellos las contraseñas SSH derivadas.

## SHA-256

- `XtraVPN.py`: `1a137a62aab933d18c9c445fb10c775f12a57424cecef2a1dd6653476c656167`
- `XtraVPN.png`: `186a7dd32eec95e9fd8280e0ef6ad8f43efad6b4d8ef033af16d3dd3862061c7`
- `config.json`: `3543c5b8f503361b1ae59e3e504c0d057db2ba640c637adc6f94ca1cb732701d`
