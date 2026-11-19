# ANALYSIS — TLS Tunnel (com.tlsvpn.tlstunnel, 8.5.0 / 516) — OFFLINE

Fecha de observación: 2026-11-19 (Tijuana). Rama de trabajo: `offline/tls`,
base `feat/version-offline-apk` @ `2996a9b2`. Analista: subagente TLS (coordinador
integra después). Sin push, merge ni deploy por este analista; sin Frida ni
captura en vivo.

## 1. Objetivo

Determinar si el formato `.tls` de TLS Tunnel puede decodificarse 100%
offline en la app SP-DECODE Offline (sin claves del servidor, sin captura en
vivo) y, si es viable, construir el decodificador nativo C++ con la misma
estructura que HC n15 y ZIVPN (oráculo Python + decodificador nativo +
harness comparado perfil por perfil + expediente).

## 2. Identidad de la app

- App: TLS Tunnel: Fast Secure VPN, desarrollador TLSVPN SERVICES LTDA.
- Package: `com.tlsvpn.tlstunnel` (confirmado en APKFab y en los enlaces de
  Google Play del canal oficial de Telegram).
- Versión del método: **8.5.0, versionCode 516** (la versión de la que se
  derivó el decodificador del servidor).
- Versión en vivo (2026-11-19): **8.5.2, build 518**, actualizada 2026-11-05
  según APKFab (18.38 MB, SHA1 `7318326872c9d7cd0f045a27cceeb229ec840742`,
  arm64-v8a + armeabi-v7a). La página de Google Play se consultó como texto
  el 2026-11-19 03:45 UTC y no expone el número de versión en el texto
  rastreado; la versión 8.5.2 se confirma por APKFab y por el MOD-listing
  (v8.5.2 b518). Changelog de 8.5.2: solo "Lib updates". 8.5.1 (2026-10-13):
  "OpenSSL 3.5.9, IO changes, Buffer size reduction, Ad reduction".

## 3. El decodificador del servidor ya existía

`decoders.json` registra `"tls": {"script": "decoders/Python/TLS.py",
"runtime": "python", "name": "TLS Tunnel"}`. El decodificador
`decoders/Python/TLS.py` implementa el contenedor completo, derivado de la
APK 8.5.0 (`Ldd.o([B)[B`), con seis perfiles de clave AES-256-GCM. También
existe el port de referencia en Kotlin
(`android/app/src/main/java/com/ghostdeveloper/spdecode/parity/TlsReferencePort.kt`,
con las claves en el asset `embedded_kotlin_profiles.json`) y la suite del
repo `tests/test_tls_decoder.py` (7 tests). Nada de esto se re-derivó aquí:
este trabajo es el **puerto nativo C++ offline** de ese método ya verificado.

### 3.1 Formato observado (no hipótesis)

1. El archivo es texto: un token Base64 (posiblemente con sufijo `:::::`),
   opcionalmente precedido de `tls://` en enlaces de texto.
2. Se toma la parte anterior al primer `:` y se eliminan los espacios.
3. Se invierte la cadena Base64 exterior y se decodifica (con padding
   reparado).
4. Contenedor: 12 bytes iniciales + C1 + IV1 (18 B) + C2 + IV2 (18 B) +
   84 bytes finales. C1 y C2 tienen (casi) la misma longitud:
   `half = ((len - 96) - 36) // 2`. Cada fragmento se invierte por separado.
5. AES-256-GCM: nonce = IV1+IV2 (36 B), etiqueta = últimos 16 B de C1+C2.
   Se prueban los seis perfiles de clave en orden fijo; **solo una etiqueta
   GCM válida entrega plaintext** (nunca plaintext parcial).
6. El plaintext es una lista de campos separados por `:` (28 posiciones en
   8.5.0). Campos con Base64 interior en los índices 4, 5, 6, 7, 9, 12, 14,
   16, 18, 19, 24, 27 (se decodifican; si el Base64 interior es inválido se
   conserva el valor original).
7. Perfil 6 (la clave histórica `AES_KEY`) usa los nombres de campo DNS
   antiguos (índices 20–23: `legacy_dns_mode`, `dnsP`, `dns_port`,
   `nameserver`, más `public_key` en 24). En los perfiles 1–5 los índices
   20–23 son booleanos y todos los campos se conservan posicionalmente en
   `_tls.fields` (índice, raw, valor).
8. `mensagem` (27) reemplaza `Ѻ` (U+047A) por `\n` y `ѻ` (U+047B) por `\r`.

### 3.2 Verificación previa (trabajo anterior, no repetida aquí)

- `docs/android/TLS_850_EHI_NESTED_DARK_BASE64.md`: "authenticated one
  private real TLS export with profile 1; the old key is profile 6. The
  private sample is not in the repository."
- `tests/test_tls_decoder.py::test_real_file_and_both_backends` registra el
  SHA-256 de esa muestra real privada:
  `cc0b05dedbe3000f980b3ba25f3f5c171a0771e27786dddfb14302d87c6ccbd2`
  (autenticada con el perfil 1; la muestra NO está en el repo y no estuvo
  disponible en esta sesión: ese test queda en `skipped`).
- La suite del repo se re-ejecutó en esta sesión: **6/6 sintéticas OK,
  1 skipped (muestra real)**.

## 4. Viabilidad offline: SÍ (para 8.5.0)

- Las seis claves son constantes fijas de la app, ya presentes en el repo
  (`decoders/Python/TLS.py` `CONFIG_KEYS`); no hay secreto de servidor, no
  hay Keystore, no hay derivación por dispositivo ni por cuenta.
- La única criptografía es AES-256-GCM, disponible en Mbed TLS 3.6.7 (ya
  enlazado por el target offline `offdecode`).
- No se necesitó ni se intentó captura en vivo, Frida ni instrumentación.
- Límite conocido: las claves son fijas **por versión de app**. Si una
  versión futura las rota, los archivos sellados con el perfil nuevo fallan
  limpiamente como `TLS_AUTH_FAILED`. Eso es un rechazo seguro, no un
  descifrado incorrecto.

## 5. La APK 8.5.2 no se pudo descargar en esta VM (evidencia)

Se intentó descargar la APK actual por `curl` (con User-Agent de navegador)
desde: APKPure (`apkpure.com`, `d.apkpure.com/b/APK/...?version=518`),
APKMirror, APKFab (`/download`), APKCombo, Uptodown y APKMonk.
Resultados 2026-11-19 ~03:45 UTC:

- APKPure / APKMirror / APKFab: **HTTP 403** a través del proxy de salida.
- APKCombo: el dominio resuelve a una página aparcada de DropCatch.com
  (sin contenido de descarga).
- Uptodown: 404 en la ruta de descarga probada.
- APKMonk / `download.apkpure.com`: sin respuesta (000).

Consecuencias honestas:

- **No se revisaron base ni splits de 8.5.2**; no se declara ninguna
  librería nativa ausente ni presente en 518 (la regla del skill exige
  revisar base + todos los splits antes de declarar ausencia, y eso no fue
  posible).
- El expediente se escribe sobre el **build 516 (8.5.0)**, el único método
  verificado, con estado `VERIFIED_SYNTHETIC` para el puerto nativo.
- La confirmación de 518 queda pendiente: hace falta la APK 8.5.2
  (descargable desde el navegador con sesión, por ejemplo APKFab/APKPure)
  o un `.tls` real exportado por TLS Tunnel 8.5.2.

## 6. Lo construido (rama offline/tls)

- `android/app/src/main/cpp/spdecode_tls_tunnel.h/.cpp` — `decodeTls()`,
  espejo exacto de `TLS.py` (mismo orden de perfiles, mismas reglas de
  campo, mismo JSON de salida que `_render_config`).
- `android/app/src/main/cpp/spdecode_offline_native.cpp` — dispatch
  `format=="tls"` y `TLS_*` en la lista de errores que se propagan tal cual.
- `android/app/src/main/cpp/CMakeLists.txt` — `spdecode_tls_tunnel.cpp`
  en el target `offdecode`.
- `android/app/src/offlineNative/.../MainActivity.kt` — `"tls"` en
  `supportedFiles`; `beginText` acepta `tls://` (pendingSuffix `"tls"`).
- `android/app/src/offlineNative/.../OfflineUi.kt` — la lista de formatos
  del diálogo de importación ahora incluye `.tls` (y `.ziv`, que faltaba).
- Expediente: este directorio `analysis/com.tlsvpn.tlstunnel/516/`.

## 7. Auditoría HMAC (política §2.2)

Ver `MANIFEST.json` (`connection_authentication`): el GCM del contenedor
es verificación de integridad/autenticidad **del archivo** (la etiqueta
autentica que el archivo fue sellado con un perfil de clave conocido).
**No se observó ningún HMAC** ni mecanismo de autenticación de conexión
VPN en este trabajo: el transporte TLSVPN y el establecimiento de sesión
no se analizaron y no se afirma nada sobre ellos. Estado `NOT_OBSERVED`
describe solo la cobertura revisada (formato de archivo), no prueba
ausencia universal de HMAC en la app.

## 8. Herramientas usadas (orden)

1. Lectura del skill, la política de evidencias y `AGENTS.md`.
2. `git ls-remote` + worktree `offline/tls` desde `2996a9b2`.
3. Lectura de `decoders/Python/TLS.py`, `TlsReferencePort.kt`,
   `tests/test_tls_decoder.py`, `docs/android/TLS_850_EHI_NESTED_DARK_BASE64.md`.
4. `browser.search` + `browser.open` (Play, APKFab) para la versión en vivo.
5. `curl` a 7 espejos de APK (todos bloqueados; ver §5).
6. `python -m unittest tests.test_tls_decoder` (oráculo del repo).
7. Escritura del decodificador C++, harness host, fixtures sintéticos.
8. `cmake` + `g++` (harness), `tools/run_harness.py` (comparación 13/13).

## 9. Intentos fallidos significativos

- Descarga de la APK 8.5.2 desde 7 espejos: bloqueada por el proxy de
  salida (403/000/parking). No se reintentó con credenciales ni con
  servicios de terceros de pago. Queda como pendiente para el coordinador
  (descarga por navegador).
- Ningún otro intento fallido: el primer puerto C++ compiló a la primera y
  el harness dio 13/13 MATCH sin correcciones de lógica (solo se corrigió
  un error de conteo de niveles `parents[]` en dos scripts Python del
  expediente y un literal no-ASCII en un `bytes` de `make_fixtures.py`).
