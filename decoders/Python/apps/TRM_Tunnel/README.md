# TRM Tunnel (com.trm.tunnel, 2.8) — catálogo, archivos .hxt y esquemas de texto

App: **TRM Tunnel**, paquete `com.trm.tunnel`, versionCode **19**,
versionName `2.8`, minSdk 24, targetSdk 36. APK analizado:
`apk/base.apk` (18 MB), SHA-256
`4e8b51c4295655be6c01c1a18431c64539d78948e481bc4c68f0400992e8a2e0`.
Fecha de trabajo: 2026-11-13. Alcance: **catálogo + archivos .hxt +
esquemas de texto**, desde cero — el repo SP-DECODE (rama
`feat/nuevas-integraciones`) no tiene cobertura de TRM Tunnel. No se
modificó el repo SP-DECODE ni se subió nada a Git. No se guardan ni se
imprimen en este documento valores descifrados, contraseñas, claves de
usuario ni datos sensibles: solo recuentos, hashes y estructura.

## Método exacto del catálogo

### Descarga

- **Endpoint activo:** `https://trmrelay.store/updater/<token>` (GET).
  La URL completa está en la constante `CATALOG_URL` del script; aquí se
  omite el token a propósito. Es una URL fija sin parámetros.
- **Dónde vive la URL en el APK:** `OpenVPNClient.z()` (classes2.dex)
  descifra la URL con LSParanoid y construye una petición `EW` con
  listener `LLJ` y error-listener `Dv(27)`, que encola en `DP`
  (`ZE.R(context)`). `EW` es la clase Request de una pila estilo Volley
  renombrada (`DP` = RequestQueue, `Db` = CacheDispatcher,
  `LH` = NetworkDispatcher).
- **Petición replicada:** GET, sin cabeceras propias: `EW.f()`
  (getHeaders) devuelve un mapa vacío y el método es GET (clave de caché
  `"0:"+url`, método 0). El transporte (HurlStack/HttpURLConnection) no
  añade cabeceras de la app. El script envía `User-Agent: Dalvik/2.1.0`
  y `Accept-Encoding: identity` (familia del agente de plataforma que
  produce esa pila). El servidor responde **200 a cualquier User-Agent**
  (verificado con Dalvik, `TRM Tunnel/2.8` y Mozilla): no hay puerta por
  UA como en APNA.
- **Sin autenticación, token de sesión, firma ni parámetros.** El token
  de la ruta es una constante fija de la app, no una credencial de usuario.

### Descifrado de la respuesta

Handler `LLJ.e` (listener de la descarga):

1. `replace(" ", "").replace("\n", "")` sobre la respuesta.
2. **`Km.c(respuesta, Km.a)`**: **Base64 estándar → XXTEA** (clase `LKm;`
   en classes2.dex; `Km.a` es la clave fija de formato `Princie!`,
   `Km.b`/`Km.d` los núcleos cifrar/descifrar por bytes, `Km.c`/`Km.e`
   los envoltorios String con Base64). Delta `0x9E5729B1`
   (en el DEX: `-1638454863`), palabras little-endian de 32 bits y tamaño
   original en la última palabra. **Idéntico al de HX Tunnel VPN** (misma
   clave, mismo delta, mismo formato); solo cambian la URL y el contenido.
3. Resultado: **JSON UTF-8 completo**, sin filtrar campos.
4. El formato **no tiene MAC**; la validación estructural no equivale a
   autenticación criptográfica.

### Flujo en la app

- Al arrancar, `a.m()` lee `filesDir/gremlin.json` si existe, si no el
  asset `assets/gremlin.json`, y lo descifra con `Km.c`.
- Al actualizar, `LLJ.e` descifra la respuesta, compara `"Version"` con
  la local (`OpenVPNClient.E()` / `w()`): si es igual muestra
  `"No Update Available!"`; si es mayor, conserva los `"Payloads"`
  locales cuyo `"message"` empiece por `"Custom Tweak"`, fusiona los
  `"Payloads"` remotos por `"friendly_name"` (insensible a mayúsculas,
  sin duplicar) y reescribe `gremlin.json` cifrado con `J90.r` =
  `Km.e` (XXTEA + Base64), mostrando `"Update Success!"`.
- Las cadenas de la app están cifradas con LSParanoid
  (`Deobfuscator$MHRTUNNELVPN$app.getString(long)`); el algoritmo es
  idéntico al de HX Tunnel VPN (mismo tag `MHRTUNNELVPN`), y las 1.803
  cadenas se recuperaron del bytecode DEX con ese algoritmo
  (`work/extract_strings.py`, `work/strings.tsv`).

## Prueba real (no simulada) — 2026-11-13

Descarga con el script entregado contra el endpoint real y descifrado
con el mismo algoritmo. Solo recuentos; el JSON completo de prueba no se
guardó (los archivos de respuesta descargados se borraron tras verificar).

| Fuente | Versión | Free | Premium | Vip | Private | Payloads | JSON (bytes) | Cifrado (bytes) |
|---|---|---|---|---|---|---|---|---|
| `assets/gremlin.json` del APK (`--apks`) | 6.47 | 25 | 0 | 0 | 0 | 753 | 270738 | 360992 |
| GET oficial (`--url --summary`) | **8.50** | **29** | 0 | 0 | 0 | **823** | — | **395432** |

- Secciones en ambos documentos: `Premium_servers`, `Vip_servers`,
  `Private_servers`, `Username`, `Password`, `Free_servers`, `Payloads`,
  `Version`, `Changelogs`.
- Campos de cada servidor: 9 claves; de cada payload: 11 claves
  (`category`, `dothost`, `friendly_name`, `host`, `message`, `method`,
  `payload`, `port`, `query`, `sausage`, `sslws`). Estructura validada
  por el script; no se listan valores.
- El `run()` offline sobre la respuesta remota guardada devuelve el
  mismo documento (versión 8.50, 29 libres, 823 payloads); `run()` con
  entrada inválida devuelve `None`.

### Incidencia de red (importante para reproducir la descarga)

El servidor corta la conexión a mitad del cuerpo con frecuencia
(`curl: (18) transfer closed with N bytes remaining`, cortes en
múltiplos de 16 KiB; `Content-Length: 395432`,
`Last-Modified: Mon, 09 Nov 2026 13:00:41 GMT`,
`Accept-Ranges: bytes`, servidor `LiteSpeed`, `connection: close`).
El script entregado hace primero el GET plano exacto de la app
(3 intentos) y, solo si no completa, reanuda por rangos
(`Range: bytes=…`, bloques de 16 KiB) con las mismas cabeceras;
la reanudación se verificó con `206 Partial Content` y el resultado se
valida por longitud y por el descifrado. Las respuestas por rangos a
veces llegan con el cuerpo vacío (cierre inmediato de la conexión);
el script reintenta cada bloque hasta 8 veces. Ese fallback es una
solución de transporte, no parte de la petición de la app.

## Archivos .hxt — flujo y clave verificados contra la libputils.so propia de TRM

- **Formato:** texto hexadecimal (una línea) → XOR repetido (clave de
  12 bytes) → UTF-8 modificado JNI (CESU-8) → JSON
  (`JSONObject.toString()` en exportación). Sin salt, IV, MAC ni firma.
- **Importación** — `OpenVPNClient.onCreate` (intent VIEW reenviado por
  `ImportTweakActivity`) y `onActivityResult` (requestCode 1, selector
  de archivos): `ContentResolver.openInputStream(Uri)` →
  `BufferedReader.readLine()` → `PUtils.pDecrypt(context, línea)` →
  `new JSONObject()`. Si `tweak_password` no está vacío → `Y()`
  (diálogo `"Password Lock"`); si está vacío → `B()` directamente. Si
  falla: `"Invalid or Corrupted File!"`.
- **Exportación** — `OpenVPNClient.X(String, JSONObject)`:
  `JSONObject.toString()` → `PUtils.pEncrypt(context, json)` → diálogo
  `"SAVE TWEAK?"`. El sufijo es `.hxt` (campo `D0`).
- **Manifiesto:** `ImportTweakActivity`, VIEW, schemes `content`/`file`,
  mimeType `*/*`, pathPattern `.*\.hxt`.
- **Políticas (se verifican DESPUÉS de descifrar; no derivan la clave),
  en `B()`/`Y()`:** `tweak_expiry` formato `yyyy-MM-dd-HH-mm`
  (`"Tweak already expired!"`), `hwid_lock`
  (`"You are not allowed to use this tweak!"`), `block_rooted`
  (`"This tweak is blocked for rooted devices!"`). Si todo pasa, `B()`
  normaliza `friendly_name` (añade ` (n)` si ya existe), guarda en
  `gremlin.json` y muestra `"Imported File Successfully!"`. El lector
  entregado recupera todos los campos sin ejecutar las políticas.
- **✅ Clave verificada contra TRM (2026-11-13).** La `libputils.so`
  del split APK de TRM fue analizada directamente (ver
  `work/NOTES_libputils.md`): `xorWithKey` @0x1476d4 carga la clave de
  12 bytes desde `.rodata` 0xc4d24 y hace `out[i] = in[i] XOR key[i % 12]`;
  `pEncrypt` @0x148928 = xor → hex, `pDecrypt` @0x148c5c = hex → xor.
  La clave del script coincide byte a byte con la de TRM; el aviso
  UNVERIFIED se retiró de `TRM_Tunnel_archivos.py`.
  - **Prueba realizada:** desensamblado de `pEncrypt`/`pDecrypt`/
    `xorWithKey`/`hexToString`/`stringToHex`; re-implementación
    independiente con la clave leída del `.so` (5/5 cifrados iguales);
    round-trip sintético `--self-test` 5/5 (15 campos; caso borde
    CESU-8 con NUL y carácter fuera del BMP correcto). **No hay ningún
    archivo `.hxt` real en el repo** (búsqueda sin resultados) con el
    que probar el extremo a extremo.
  - **Pendiente:** un `.hxt` real exportado por TRM Tunnel 2.8, solo
    para confirmar el extremo a extremo.
- **`.sks`: no hay nada.** Ninguna referencia a `.sks` en el manifiesto,
  en las 1.803 cadenas descifradas ni en el bytecode. No se construyó
  ningún decodificador `.sks`.

## Esquemas de texto/enlaces — ninguno propio en vivo

- **Manifiesto:** no hay ningún intent-filter con esquema propio de la
  app (solo `genericidp`/`recaptcha` de Firebase Auth). No se construyó
  `TRM_Tunnel_textos.py`.
- **`hxt://`:** existe como literal LSParanoid en `OpenVPNClient.<init>`
  (junto a `.hxt` y `HXTUNNELVPN`), pero su resultado se descarta ahí y
  **ningún código vivo lo parsea**: no hay lectura de portapapeles ni
  parseo de texto con ese prefijo; las únicas 3 llamadas a
  `PUtils.pDecrypt` son la importación de archivos (2) y el arranque de
  Psiphon (1). Es código muerto heredado de la plantilla.
- **`vmess://`:** solo aparece dentro de `Ld60.run` como plantilla de
  configuración XRay (el motor construye el JSON de V2Ray cuando el
  perfil usa vmess); no es un importador de enlaces de usuario.
- **`OPEN_URL:`:** acción dentro de la app (`OpenVPNClient.T`): si el
  campo de un perfil empieza por `OPEN_URL:`, se quitan 9 caracteres y
  se abre el resto con un intent `ACTION_VIEW`. No es un esquema URI de
  importación.

## Archivos entregados

- `TRM_Tunnel.py` — catálogo, solo stdlib. `decode()` + `run()` + CLI
  (`--url`, `--apks`, `--stdin`, archivo posicional, `-o/--output`,
  `--summary`). SHA-256:
  `a01894f42139f44b61d0e5c4a565240fae51232eda996823a88b0a4638920ded`.
  Uso: `python3 TRM_Tunnel.py --url --summary` (remoto),
  `python3 TRM_Tunnel.py --apks apk/base.apk --summary` (incrustado).
  Al guardar usa `O_EXCL` y modo `0600` y no sobrescribe.
- `TRM_Tunnel_archivos.py` — archivos `.hxt`, solo stdlib. `decode()` +
  `run()` + CLI (archivo posicional, `--text`, `-o/--output`,
  `--summary`). **Clave verificada contra la libputils.so propia de
  TRM** (ver § Archivos y `work/NOTES_libputils.md`).
  SHA-256:
  `8faf7fc8b928013793f89c75666254a3564632ddeb3655ba4892d720a083d6fc`.
- `TRM_Tunnel.png` — icono copiado **sin recodificar** de
  `res/drawable/ic_app_icon.png` (512×512, RGBA, PNG). SHA-256:
  `d0618db1cf179970dcb0bc185824510e69b97ac0029e7d169e43930a526df8f2`.
- `README.md` — este documento.
- `apk/base.apk` — APK analizado (SHA-256 arriba).
- `jadx-out/` — decompilación jadx 1.5.3 (parcial: dos pasadas murieron
  por OOM del sistema al ~62 % y ~84 % con otros jadx en paralelo; las
  clases clave se verificaron además por bytecode DEX).
- `work/` — análisis: `strings.tsv` (1.803 cadenas LSParanoid
  descifradas con su clase/método), `bytecode.txt` (volcado de las
  clases clave), `llj_km.txt` (LKm/LLJ/a), `ew.txt` (pila HTTP),
  `extract_strings.py`, `deobfuscate_lsparanoid.py`,
  `dump_bytecode.py`, `manifest.xml`, `jadx.log`/`jadx2.log`,
  `ic_app_icon.png`.

## Contrato de salida

- Catálogo: `decode()` devuelve el JSON completo del catálogo como
  `dict` (secciones `Free_servers`, `Premium_servers`, `Vip_servers`,
  `Private_servers`, `Payloads`, `Version`, `Changelogs`, `Username`,
  `Password`); `run()` devuelve ese JSON como texto o `None` si la
  entrada no es un catálogo válido. `--summary` solo emite versión y
  recuentos, nunca valores descifrados.
- Archivos: `decode()` devuelve el JSON del perfil `.hxt` como `dict`
  con todos sus campos; `run()` devuelve ese JSON como texto o `None`.
  `--summary` solo emite claves y recuento de campos.

## Pendientes

1. **Archivos .hxt:** probar contra un `.hxt` real exportado por TRM
   2.8 (no existe ninguno en el repo). La clave y el algoritmo ya están
   verificados contra la `libputils.so` del split APK; el `.hxt` real
   solo confirmaría el extremo a extremo.
2. **jadx completo:** la decompilación total murió dos veces por OOM;
   si hace falta el resto de clases, relanzar jadx sin otros trabajos
   en paralelo o con más memoria.
3. El endpoint remoto cambia con frecuencia (6.47 incrustado → 8.50 en
   vivo el 2026-11-13); el script no fusiona perfiles locales (eso lo
   hace la app en `LLJ.e`).
