# Click Tunnel 1.0 — ANALYSIS

Fecha de verificación: 2026-11-17. Entorno: Python 3.12.3 del sistema
y venv con pycryptodome 4.4.0. Alcance: catálogo + archivos
`.sup`/`.wsuiou` + esquemas de texto/nube. Estado global: **PARTIAL**
— catálogo VERIFIED en vivo, archivos VERIFIED_SYNTHETIC, nube
`xfsd://` PENDING sin clave real.

## 1. Método del catálogo

- Endpoint: la `DefUpdateURL` guardada en SharedPreferences; su valor
  por defecto (asset incrustado `res/raw/noobdev.js`) es la URL GitHub
  raw en la constante `CATALOG_URL` del script. URL fija, sin
  parámetros. La URL `updater` es solo la comprobación de actualización
  del paquete, no el catálogo.
- Petición: `L0` caso 10 ("FetchData") hace un GET plano
  (`HttpURLConnection`, timeouts connect/read de 5.000 ms, sin
  cabeceras propias, exige HTTP 200). El script envía
  `User-Agent: Dalvik/2.1.0`. Sin autenticación, token, firma ni
  parámetros. GitHub raw responde 200 a cualquier User-Agent
  (verificado en vivo).
- Descifrado: (1) `I20.a` capa externa: Base64 estándar →
  **XXTEA modificado** (delta `0x9A7393B4`, rondas `(52/n)+6`,
  palabras little-endian, longitud original en la última palabra;
  clave = primeros 16 bytes del UTF-8 de 32× U+3164). Resultado: JSON
  UTF-8 completo, con los campos de texto aún cifrados. (2) Campos
  `C0972Sm.c`: **AES-256/CFB128/NoPadding**; clave = SHA-256 de una
  semilla de 83 caracteres (61 espacios + `'` + 12 espacios + `.` +
  8 espacios); IV = `AbstractC1943eS.c`. Se aplica a campos de nivel
  superior, `Servers[]` y valores anidados `SlowDNS`/`UDP`.
  (3) Campos `C0972Sm.d`: **AES/CBC/PKCS7Padding**; clave = hex MD5 en
  ASCII minúsculo (32 bytes) de una semilla de 63 caracteres
  (29 espacios + `.` + 33 espacios); IV = `OO0.b`. Se aplica a
  `Tweaks[]`. El `Flag` de los tweaks es texto plano (`NOOB_DEV`).
  Las cadenas vacías quedan vacías. El formato **no tiene MAC**.
- Flujo en la app: al arrancar se lee el asset (o el catálogo guardado)
  y se descifra con `I20.a`; al actualizar, `H01.d` descifra y compara
  `"Version"` con la guardada; si es mayor, guarda la respuesta cruda
  en SQLite y parsea los campos. El script no fusiona perfiles locales.

## 2. Catálogo en vivo (2026-11-17)

| Fuente | Versión | Servidores | Tweaks | JSON (bytes) | Cifrado (bytes) |
|---|---|---|---|---|---|
| `res/raw/noobdev.js` del APK (`--apks`) | 1.0.0 | 1 | 1 | 2.005 | 2.684 |
| GET oficial (`--url --summary`) | **5.1.8** | **7** | **18** | 22.441 | 29.932 |

- Secciones: `Version`, `Message`, `DefUpdateURL`, `updater`,
  `updatemsg`, `RewardAd_ID`, `Interstitial_ID`, `Banner_ID`,
  `AppOpenAd`, `RewardInter_ID`, `cardMessage`, `cardLink`, `defTime`,
  `addTime`, `bonus`, `MyBool`, `unlimited`, `versioncode`, `useunity`,
  `isforce`, `rewardInt`, `show_release`, `Servers`, `Tweaks`.
- Servidores: 7 (todos `NoobLevel` 0; `Protocol` 0, 1 y 2). Un servidor
  trae `UDP` anidado y otro `SlowDNS` anidado, ambos descifrados.
- Tweaks: 18 (`Mode` 1, 2, 5 y 6). Con `Payload` no vacío: 12; con
  `Sni` no vacío: 1; con `v2rayjson`/`v2Sni` no vacío: 0.
- **Valores sin descifrar: ninguno.** (El `DNSTTKey` descifrado es un
  token hexadecimal de 64 caracteres por naturaleza, no un resto
  cifrado.)
- `run()` offline sobre la respuesta guardada
  (`work/live_response.txt`) devuelve el mismo documento en 0,09 s
  (tope del worker: 20 s). `run()` con entrada inválida devuelve `None`.

### Hallazgo: `decode()`/`run()` NO quitan las APIs de descarga

El documento descifrado lleva sus propias URLs en `DefUpdateURL`
(= `CATALOG_URL`) y `updater` (URL de comprobación de actualización en
otro repositorio GitHub del mismo autor).
Solo `main()` las quita al guardar/imprimir. Verificado en esta tarea:
`run()` sobre `live_response.txt` devuelve 17.570 B CON ambas claves;
quitando esas dos claves el documento es idéntico al `live.json`
entregado (17.432 B). En el flujo supplied, `decode_one()` llama a
`module.decode()` por defecto, así que **el resultado llevaría las
APIs de descarga** salvo que se añada una rama en `supplied_bridge.py`
que quite ambas claves (patrón RH/JK). Ver REPORT.md §5.

## 3. Archivos `.sup` / `.wsuiou`

- Formato: Base64 (Android DEFAULT, saltos cada 76 caracteres) de
  `nonce[12] || ciphertext || tag[16]` → **AES/GCM/NoPadding**,
  etiqueta de 128 bits; clave = primeros 32 bytes del UTF-8 de
  `AbstractC2334hX.a` (84 caracteres: 33 espacios + `*` + 28 espacios
  + `'` + 12 espacios + `.` + 8 espacios). Nonce aleatorio de 12 bytes.
  Sin salt, IV fijo ni firma.
- Contenido: tras descifrar, el texto debe empezar por `Click Tunnel`
  y el resto es JSON. Los campos `Payload`, `SNIHost`, `ProxyHost`,
  `ProxyPort`, `DNSHost`, `UDPhost`, `UDPobfs`, `UDPauth`, `UDPUpMbps`,
  `UDPDownMbps`, `UDPPort`, `v2rayConfig`, `v2raySni` y
  `WireGuardConfig` van además cifrados individualmente con la misma
  clave (nonce aleatorio por campo) y se descifran al usarlos; el lector
  aplica esa misma regla. El resto de campos es texto plano.
- Importación: `Main.onCreate` (intent VIEW, `.*\.sup`) y
  `onActivityResult` (selector `GET_CONTENT */*`) → `Main.M`.
  Exportación: `ExportActivity.m()` escribe `<nombre>.wsuiou`.
  **Quirk:** la exportación escribe `.wsuiou` pero el filtro VIEW es
  `.sup`; el selector interno acepta cualquier archivo. El lector
  acepta ambas extensiones (mismo contenido).
- Políticas (se verifican DESPUÉS de descifrar; no derivan la clave):
  `ExpireDate`, `RootBlock`, `DeviceID`, `PSInstall`, `isPassON`
  (comparación con `MyPass`). El lector recupera todos los campos sin
  ejecutar las políticas. Quirk: con `TunnelType` 5, `v2rayConfig` se
  escribe `""` y `v2raySni` cifrado; con `TunnelType` 9 es al revés.
- `.sks`: no hay nada. No se construyó decodificador `.sks`.

## 4. Esquemas de texto/nube

- Portapapeles (catálogo): el menú `offline_update` aplica `I20.a` al
  portapapeles; cubierto por `Click_Tunnel.py` (`--stdin`).
- QR: la exportación QR codifica el texto completo de `m()` (mismo
  formato `.sup`/`.wsuiou`); cubierto por `Click_Tunnel_archivos.py`
  (`--text`).
- **`xfsd://` (nube): NO es un esquema URI registrado** (no hay
  intent-filter para `xfsd`): es solo una clave de texto. La exportación
  a nube sube `m()` a Firebase Storage
  (bucket `click-tunnel.firebasestorage.app`) como `<clave>.wsuiou` y
  muestra `CONFIG KEY: xfsd://<20 caracteres alfanuméricos minúsculos>`.
  La importación descarga ese objeto y lo pasa a `Main.M`. El diálogo
  usa lo tecleado tal cual como nombre del objeto, sin quitar el
  prefijo — la clave de 20 caracteres se teclea sin el prefijo.
  **No verificado en vivo:** no existe ninguna clave `xfsd://` real;
  no se construyó un descargador de nube. El contenido descargado sería
  el mismo formato `.wsuiou` que ya decodifica el lector. **NO se
  registra como formato de texto.**

## 5. Auditoría HMAC

- Archivos/catálogo: integridad por tags AES-GCM (AEAD), no HMAC.
  El catálogo no tiene MAC.
- Derivación: SHA-256 / MD5 de semillas fijas, no HMAC.
- Transporte VPN: no revisado.
- Autenticación de conexión: no observada (GET plano sin firma).

## 6. Pendientes

1. Archivo `.sup`/`.wsuiou` real exportado por la app (extremo a extremo).
2. Clave `xfsd://` real (descarga de nube).
3. Rama `decode_one` en `supplied_bridge.py` para quitar
   `DefUpdateURL`/`updater` (ver §2).
