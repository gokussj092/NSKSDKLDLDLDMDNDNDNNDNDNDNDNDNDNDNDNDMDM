# ANALYSIS — ANY VPN build 40 (versionCode 40)

Paquete: `com.markvpnpro.pinas`, versionName literal `16kb-page-size`.
Fuente de los hechos: `~/workspace/catalogs/anyvpn/README.md` + `ANY_VPN.py` y
`decoders/Python/apps/ANY_VPN/ANALYSIS.md` (método base documentado antes).
Observado: 2026-11-17 (actualización v5.84 → v7.3). Estado global: **VERIFIED**
para el catálogo en vivo; archivos `.dtk` **VERIFIED_SYNTHETIC** (sin muestra real).

## 1. Objetivo

Documentar la actualización del método de catálogo / archivo de esta app con evidencia
reproducible, separando observación, hipótesis y verificación, sin secretos y sin afirmar
lo no probado. Este expediente es NUEVO: en el repo no existía
`analysis/com.markvpnpro.pinas/`; el método base vive en
`decoders/Python/apps/ANY_VPN/` (README/TESTING/ANALYSIS/manifest).

## 2. Muestra: como se obtuvo, hashes

- APKS de espejo público (versión de Google Play); hash en MANIFEST.json > inputs.
- Sin APK, perfiles reales ni datos de usuarios en este expediente.
- Catálogo en vivo: solo el hash del cuerpo crudo (115820 B, v7.3); el cuerpo crudo
  NO se guarda aquí (contiene credenciales reales de servidores). Referencia descifrada:
  `~/workspace/catalogs/anyvpn/live.json`.

## 3. Método

1. **Arranque:** `MainBaseActivity.getJSONObject()` lee `<filesDir>/Servers.js` si existe;
   si no, descifra el fallback embebido `c_11.conf` con `Parser.parseToString` (AES, clave `red1987`).
2. **URL del catálogo:** `ActivityUi.checkResources()` toma la preferencia `UpdateApi`
   (vacía por defecto; se llena desde la clave `config_url` del propio catálogo), le quita
   espacios/saltos de línea (`VPNUtil.decrypt`) y aplica una sustitución de 26 caracteres
   CJK→ASCII, luego lanza `JsonManager$ServerUpdate`.
3. **Descarga:** `JsonManager$ServerUpdate.doInBackground()` — **GET** a la URL, sin headers
   extra, UA por defecto de OkHttp **`okhttp/5.0.0-alpha.12`**, sin body.
4. **Formato del catálogo** (embebido y en vivo, idéntico):
   `base64( AES-256-CBC( JSON, key = SHA-256("red1987"), IV = 16 × 0x00, PKCS7 ) )`.
5. **Campos cifrados** dentro del JSON (`ServerIPHost`, `ServerUser`, `ServerPass`,
   `vaddress`/`vhost`/`et*`, `config_url`, `account_api`, `Payload`, `Squid`, `SNIHost`,
   `vsni`, …): mismo base64/AES; el texto plano resultante está en caracteres CJK que se
   sustituyen con la tabla de 26 pares (la misma de `checkResources`). Un campo vacío es
   un bloque completo de padding `0x10` → `""`.
6. **Contraseña secundaria:** `Parser.a` usa `ir1987` (p. ej. el blob del host SNI en
   `TunnelVPN.c2()`).

### La corrección de esta actualización (dos bugs encadenados, una sola causa raíz)

- **Bug 1 — investigación (`deobfuscate.py`):** las cadenas de la app están ofuscadas con
  `com.panda912.muddy.ObfuscatedString` (`java.util.Random`). El primer decodificador tenía
  un bug en `nextLong()`: trataba la mitad baja como *unsigned*, cuando
  `Random.nextLong()` la suma como *signed* (`(hi<<32) + lo_signed`). Eso corrompía 1 byte
  de cada 8 y producía valores falsos (`SHA-556`, `UTF-9`, `AES/DBC/...`, host `abc.gnsbd.top`,
  JSON `...a2ce74a.json`, `free.php`) y la conclusión errónea de que el AES estaba roto y el
  catálogo muerto. Con el decodificador corregido (`tools/deobfuscate.py` en este expediente)
  todo descifra limpio: las URLs reales son `https://abc.dnsbd.top/...`,
  `.../8e8987d108922a1ce74a.json`, `freeze.php`, y el AES funciona en runtime.
- **Bug 2 — runtime (`codec.py` del repo):** el codec descifraba el AES pero NUNCA aplicaba
  la sustitución CJK→ASCII a los valores de campo. La tabla de 26 pares sí se conocía (se usó
  para recuperar la URL en `checkResources`), pero no se aplicaba a los campos. Resultado
  verificado en vivo sobre el cuerpo v7.3: `ServerIPHost`/`ServerUser`/`ServerPass`/`Payload`/
  `config_url`/`account_api` salían en CJK (p. ej. host `く듌.山大.듌.大く땀` en vez de
  `45.81.5.149`). Las cuentas (13 servidores, 91 redes en v5.84) eran correctas; los valores no.
  Como el catálogo embebido v1.1 (misma build 40) ya trae los campos sustituidos, el defecto
  casi seguro afectaba también a v5.84 — pero no sobrevive ninguna muestra cruda de v5.84 para
  probarlo directamente; se registra como inferencia, no como hecho.
- **Corrección portada:** `desubstitute()` + tabla SUB de 26 pares en `codec.py`, aplicada en
  `open_fields()` (cubre catálogo y `.dtk`); `decode_catalog()` elimina `config_url` y
  `account_api` del JSON de resultado (regla del catálogo, 2026-11-15). URL, clave, UA,
  `download()` y `server_catalog_decoder.py`/`file_decoder.py` sin cambios.

## 4. Herramientas, por orden, con comandos

1. Extracción del APKS (base.apk + splits arm64/es/xhdpi) en `~/workspace/catalogs/anyvpn/apks/`.
2. Decompilación / inspección DEX (jadx; versión no registrada en los logs de origen: UNKNOWN).
3. `tools/deobfuscate.py` — decodificador ObfuscatedString corregido (este expediente).
4. Script de investigación `~/workspace/catalogs/anyvpn/ANY_VPN.py`:
   `python3 ANY_VPN.py --self-test` (8/8, incluye descarga en vivo).
5. Codec del staging: `python3 -m py_compile decoders/Python/apps/ANY_VPN/codec.py`.
6. Tests de este expediente: `python3 analysis/com.markvpnpro.pinas/40/tests/test_method.py`
   (vectores sintéticos, sin red; requiere PyCryptodome).

## 5. Rutas remotas (sin tokens ni endpoints sensibles)

- Catálogo: GET a la URL fija del `config_url` descifrado del catálogo embebido, UA
  `okhttp/5.0.0-alpha.12`, sin headers extra ni body. Sin redirecciones.
- No se consultan APIs de login, caducidad, cuentas o congelación. `freeze.php` (registro
  de servidor gratis) da 404: endpoint eliminado; no afecta al catálogo.

La URL completa de descarga vive SOLO en el script operativo (`codec.py` / broker) y en
`supplied-integrations.json` cuando aplique. Por la regla de Pedro, los JSON de resultado
de catálogo NO llevan las APIs de descarga: solo datos del catálogo, todo descifrado.

## 6. Auditoría HMAC de conexión (política §2.2)

La mera presencia de una librería HMAC no confirma nada. Estados por ámbito:

| Ámbito | Estado | Evidencia / límite |
|---|---|---|
| catalog_file_integrity | NOT_OBSERVED | AES-CBC sin MAC: la integridad se comprueba por padding PKCS7 y parseo JSON tras el descifrado. Sin HMAC observado. |
| catalog_download_auth | NOT_OBSERVED | GET simple sin firma ni auth. Sin HMAC observado. |
| crypto_derivation | NOT_OBSERVED | Clave AES = SHA-256 UTF-8 directo de la constante de build; sin PBKDF2 ni HMAC en la derivación. |
| vpn_transport | NOT_OBSERVED | No se observó una conexión VPN en vivo ni MAC del transporte. |
| connection_auth | NOT_OBSERVED | No se observó autenticación de conexión VPN. |

Nunca se guardan valores de claves ni entradas/salidas de hooks en este expediente.
(Las constantes de build `red1987`/`ir1987` viven solo en el script operativo, como en el
resto de decodificadores del repo; no son credenciales de usuario.)

## 7. Alcance real y cambios frente a builds previos

- Lo verificado en vivo es solo para esta versión (versionName `16kb-page-size`,
  versionCode 40); no se afirma compatibilidad con builds previos o posteriores sin prueba.
- Un fixture sintético demuestra la lógica implementada, NO compatibilidad con una versión
  real ni conectividad remota: en RESULTS.md se distingue VERIFIED_REAL / VERIFIED_SYNTHETIC /
  REQUIRES_DEVICE / NOT_AUTHORIZED / NETWORK_UNAVAILABLE.
- v5.84 → v7.3: misma URL, misma clave, mismo UA. Cambian los contenidos: 13 servidores
  (igual), 91 → 89 redes. 41 redes con `Payload` no vacío; 56 con `SNIHost`.

## 8. Archivos de este expediente

- `MANIFEST.json`, `ANALYSIS.md` (este archivo), `REPRODUCE.md`, `RESULTS.md`,
  `DEPENDENCIES.md`, `dependencies.lock.json`
- `tools/deobfuscate.py` (decodificador ObfuscatedString corregido)
- `tests/test_method.py` + `tests/fixtures/synthetic_catalog.json` (vectores SINTETICOS)
