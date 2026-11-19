# SSC Custom — analysis (dev.epro.ssc, 4.3.13 / 96)

## 1. Objetivo

Integrar la decodificación de archivos `.ssc` y enlaces `ssc://` en la
app **offline** de SP-DECODE (rama `feat/version-offline-apk`), sin claves
del servidor, sin red y sin captura en vivo. Estado final:
**VERIFIED_SYNTHETIC** — el formato está verificado por round-trip contra
el decodificador del servidor y contra el decodificador nativo C++, pero
**no existe aún una muestra real** exportada por la app.

## 2. Identidad de la app (observación)

- **Nombre en SP-DECODE:** SSC Custom. **Nombre en Play:** SSH Custom.
  La comunidad la llama "SSC Custom" (SSC = SSH Custom); el paquete es
  `dev.epro.ssc`, del equipo **ePro Dev. Team** (el mismo de HTTP Custom).
- **Versión en vivo (Play, verificado 2026-11-18/19):**
  v4.3.13, versionCode **96**, actualizada el 29 de octubre de 2026,
  ~950 mil instalaciones, 4.2 estrellas (AppBrain, último rastreo hace
  9 días). Fuentes: Play
  `https://play.google.com/store/apps/details?id=dev.epro.ssc` y
  AppBrain `https://www.appbrain.com/app/ssh-custom/dev.epro.ssc`.
- **Registro en SP-DECODE:** `decoders.json` → `"ssc":
  {"script": "decoders/Python/SSCCUSTOM.py", "runtime": "python",
  "name": "SSC Custom"}`; texto `ssc://` en
  `cloud/web/content/text-formats.json` y `SSC_TEXT_INTEGRATION.md`.
- **No hay expediente previo** en `analysis/` para este paquete: este
  dossier es el primero. El corpus dorado A23 ya cubría el formato en
  Linux con un fixture sintético de una sola capa
  (`tests/golden/expected/ssc-chacha20.txt`, input SHA-256
  `9ba6949af73dfbbc8da8b54758368c8f7e14c74bbf106617726b8542c8ecc5b8`).

## 3. Formato y cripto (observación → verificación)

Algoritmo tomado del decodificador del servidor
(`decoders/Python/SSCCUSTOM.py`, no modificado) y reimplementado de
forma independiente en `tools/ssc_oracle.py`:

| Capa | Construcción |
| --- | --- |
| Archivo `.ssc` | Texto UTF-8: hex del cifrado L1 (se ignoran espacios). |
| Enlace `ssc://` | `ssc://` + hex **invertido** (el resto de la cadena al revés). |
| L1 | ChaCha20 (variante original DJB: nonce 64 bits, contador 64 bits, **contador inicial 1** = `seek(64)` en PyCryptodome), clave L1, nonce fijo = uint64 LE `0xf7479d9f87f3d074` (`74 d0 f3 87 9f 9d 47 f7`). Resultado: JSON. |
| Una capa | El JSON L1 tiene `"a"` = lista de objetos de perfil. |
| Dos capas | El JSON L1 tiene `"a"` = 16 hex (nonce L2, 8 bytes) y `"c"` = hex del cifrado L2; L2 = ChaCha20 (clave L2, ese nonce, contador 1) → JSON con `"a"` = perfiles. |
| Campos internos (L3) | En un perfil, `"b"` es una clave de usuario de 32 hex. Nonce interno = `hex-decode(reverse(key[16:32]) + "68" + key[0:16])[:8]`. Los campos `g,h,l,o,p,v,x,i,w` que sean hex de **más de 16 caracteres** se descifran con ChaCha20 (clave L3, nonce interno, contador 1) y se cortan en el primer NUL. |
| Mapa de claves | Una letra → nombre legible (`a`=CONFIGS, `b`=NOTE, `c`=EXPIRY DATE, `e`=CONFIGNAME, `f`=PAYLOAD ENABLED, `g`=PAYLOAD, `h`=PROXY, `i`=PROXY PORT, `j`=TYPE, `k`=PROXY ENABLED, `l`=ADDRESS, `m`=PORT, `n`=IS PREMIUM, `o`=USERNAME, `p`=PASSWORD, `q`=TIMEOUT, `r`=PROTOCOL, `s`=VERSION, `t`=ENCRYPTION, `u`=COMPRESSIONLEVEL, `v`=DNS, `w`=NSSERVER, `x`=PUBKEY, `y`=ISDEFAULT, `z`=LOCALPORT). No hay clave `d`. |

Las tres claves (L1/L2/L3) y el nonce son **constantes embebidas en la
app y ya presentes en el repo** (`SSCCUSTOM.py`, `SscPort.kt`). No hay
secreto del servidor, ni cuenta, ni descarga, ni Keystore: el formato
puede correr **100% offline**. Verificado: el oráculo y el decodificador
del servidor coinciden en los 4 fixtures positivos y rechazan los 6
negativos (`verify.py`, 24/24).

## 4. Quirks del decodificador del servidor (observación, reproducidos a propósito)

Dos comportamientos del servidor, confirmados ejecutando el decodificador
real sobre los fixtures (no son errores de este dossier):

1. **Archivos de dos capas: los perfiles conservan las claves de una
   letra.** En la rama de dos capas, el servidor renombra `"a"` →
   `"CONFIGS"` antes de llamar a `_process_configs`, que busca `"a"`;
   al no encontrarla, los perfiles no se procesan ni se renombran. El
   resultado tiene `CONFIGS: [{"e": ..., "l": ..., "m": ...}]`. El
   decodificador nativo reproduce esto exactamente (mismo `lookup "a"`).
   Si el servidor se corrige algún día, hay que realinear el offline.
2. **Campos internos L3 de 16 hex o menos (≤ 8 bytes de texto plano)
   quedan cifrados.** La guarda `len(enc_val) > 16` salta el descifrado
   de valores cortos. En el fixture `inner_encrypted.ssc`: `DNS`
   (`"8.8.8.8"`, 7 bytes → 14 hex), `PROXY` (`"10.0.0.1"`, 8 bytes →
   16 hex) y `NSSERVER` (`"9.9.9.9"`) llegan como hex sin descifrar,
   mientras `ADDRESS`, `USERNAME` y `PASSWORD` (más largos) sí se
   descifran. El oráculo y el C++ reproducen la guarda.

## 5. Herramientas y pasos (por orden)

1. Leídos `SKILL.md` (spdecode_catalog_decoding),
   `analysis/METHOD_EVIDENCE_POLICY.md` y `AGENTS.md`; creado el
   worktree `offline/ssc` desde `feat/version-offline-apk` @ `2996a9b2`.
2. Estudiado `decoders/Python/SSCCUSTOM.py`, el port Kotlin
   `parity/SscPort.kt` (que ya implementa el mismo ChaCha20-64 bits en
   `parity/LegacyChaCha8.kt`) y el generador dorado A23
   (`tests/golden/a23_generators.py::ssc_bytes`).
3. Verificada la versión en vivo en Play/AppBrain (v4.3.13 / 96).
4. **Intento de descarga del APK (fallido, documentado):**
   `APKPure .../download` → HTTP 403 a curl; `APKCombo .../download/apk`
   → HTTP 200 pero cuerpo HTML (la descarga exige JS/token);
   APKMirror → sin conexión (HTTP 000). No hay `apktool`/`jadx`/`adb`
   en la VM. Por tanto **no se pudo listar librerías nativas por
   split**; no hace falta para este formato (ChaCha20 + JSON puros, sin
   dependencia nativa) y el decodificador no usa ninguna librería de la
   app. La confirmación de que 4.3.13 no cambió el sobre queda pendiente
   de un archivo real exportado (ver §7).
5. Escrito el oráculo `tools/ssc_oracle.py` (reimplementación
   independiente) + `tools/make_fixtures.py` (4 positivos, 6 negativos,
   1 vector KAT ChaCha20) + `tools/verify.py` (oráculo vs servidor).
6. Escrito el decodificador nativo `android/app/src/main/cpp/
   spdecode_ssc.{h,cpp}` (ChaCha20-64 implementado a mano, espejo de
   `LegacyChaCha8.kt`; la variante IETF de 96 bits de mbedTLS **no**
   sirve aquí) + `tools/host_ssc_test.cpp` /
   `tools/build_host_harness.sh` (compila el .cpp de producción sin
   cambios contra el `json.hpp` fijado en CMakeLists).
7. Conectado: dispatch `decodeNative` (formato `"ssc"` + prefijo de
   error `SSC_`), `CMakeLists.txt`, `supportedFiles` + ruta `ssc://` en
   `MainActivity.kt`, lista de formatos en el diálogo de `OfflineUi.kt`
   (se añadió también `.ziv`, que ya estaba soportado pero no listado).

## 6. Alcance real

- **Archivo `.ssc` y texto `ssc://`: VERIFIED_SYNTHETIC** (round-trip
  sintético completo, ver RESULTS.md). No es VERIFIED: falta un archivo
  real exportado por SSC Custom 4.3.13.
- **Catálogo:** no aplica; SSC Custom no tiene catálogo en la nube de
  SP-DECODE.
- **Autenticación de conexión (HMAC, §2.2 de la política):**
  NOT_OBSERVED en el ámbito revisado (formato de archivo/texto). El
  sobre es ChaCha20 + JSON sin MAC; no hay negociación por sesión ni
  material de Keystore. Esto no prueba que la app no use HMAC en su
  transporte VPN/SSH en vivo, que no se investigó. Detalle en MANIFEST.

## 7. Pendiente (qué muestra falta)

**Un archivo `.ssc` real exportado por SSC Custom 4.3.13
(`dev.epro.ssc`, versionCode 96) en un teléfono, o un enlace `ssc://`
real.** Con él se promueve el estado a VERIFIED y se confirma que la
versión actual no añadió una capa nueva. Idealmente uno de una capa y,
si existe, uno de dos capas. No se necesita captura en vivo ni Frida
para esto: basta exportar desde la app.
