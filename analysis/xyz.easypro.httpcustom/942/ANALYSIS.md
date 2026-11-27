# HTTP Custom 8.1.5 (build 942) — port n19 al decoder C++ offline

- Fecha: 2026-11-27 (Tijuana).
- Paquete: xyz.easypro.httpcustom, versionName 8.1.5, versionCode 942.
- Rama offline: feat/version-offline-apk, head remoto verificado
  f75c675155cb0eee2867d7283a54f614c2af654b.
- Base del port: `spdecode_http_custom.cpp` del head remoto
  (650 líneas, SHA-256 541f7ec4f7074f5af5c58b287785f22374cfb489).
  El worktree local estaba desactualizado (le faltan 148 archivos) y NO se
  usó. Entrega: `spdecode_http_custom.cpp.new` (743 líneas, +93).
- Referencia lógica: el motor Python de la nube, commit 807c71d6
  (`decoders/Python/apps/HTTP_Custom/codec.py` + `crypto.py`), y el script
  aprobado `hc942_banner.py`. El expediente de la nube está copiado
  íntegro en `cloud-src/` (solo lectura, procedencia registrada).

## 1. El método n19 (observado, no inventado)

HCCFG b=14 / e=n19, n=942, `c=s1`, `d=h1`, `f=["ssh","profiles"]`,
semilla `g` de 32 B, secciones `i` + 2 `j`, sobre exterior HCX4-v4 sin
cambios. Sin cápsula `p` ni slots HWID `o` en los 3 archivos reales.

- Prestates: N19_INNER
  (0xbe68d8a0, 0x4972cc8b, 0xfb623f3a, 0x71b28162, 0xfefae202, 0xb892b6d7,
  0x61211cb5, 0x47b148ae), N19_OUTER
  (0x29ec5b88, 0xe7aacc30, 0xe7f995a0, 0xfe072dfb, 0x1d8962b0, 0x035437db,
  0xbba98361, 0x4b991e23).
- `native_fold_n19(data) = sha256_from_state(N19_OUTER,
  sha256_from_state(N19_INNER, 0xf1 || CERT_SHA256 || data))`. Mismo
  prefijo 0xf1 y mismo CERT
  (95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181) que
  n15; solo cambian los prestates.
- AAD = `HCCFG|14|XCHACHA20P1305|NATIVE-HKDF-SHA256|n19|`
  + PKG + `|1|` + features + protectionAAD + `|` + build.
- content = native_fold_n19(aad); key = HKDF(content + passwordKey, seed,
  `hc-config-content-v14`). La passwordKey (Argon2id, igual que n15) se
  concatena ANTES del HKDF de contenido, solo cuando el archivo está
  protegido. Sin slot HWID en n19.
- Part keys: MISMA etiqueta que n15: HKDF(key, `hc-config-part-v12`,
  aad + 0x00 + label + extra). Solo la etiqueta de contenido cambia (v14).
- `app_version`: build 942 → `8.1.5 (942)`.

## 2. Qué cambió en el C++ (diff conceptual)

Archivo modificado: `android/app/src/main/cpp/spdecode_http_custom.cpp`
(entrega como `.cpp.new`; el original NO se sobrescribió). El `.h` NO
cambia: el entry point `decodeHttpCustom(raw, password, hwid)` es el
mismo, así que no hay `.h.new`.

1. `N19_INNER_STATE` / `N19_OUTER_STATE` tras `N15_OUTER_STATE`.
2. `nativeFoldN19()` tras `nativeFoldN15()`: misma construcción, mismos
   0xf1 + CERT, prestates n19. Reutiliza `fromState()` (SHA-256 con
   prestate vía `MBEDTLS_PRIVATE`, igual que n15).
3. `Material` gana `bool n19=false` (junto a `n15`).
4. `deriveN19()` espejo exacto de `deriveN15()`: AAD `HCCFG|14|…|n19|…`,
   `nativeFoldN19`, HKDF `hc-config-content-v14`, `PASSWORD_REQUIRED`
   cuando está protegido y no hay contraseña, `return {key,aad,false,true}`.
5. `derive()`: rama `modern && schema==14` con `e=="n19"` antes de la
   rama n15. Cualquier otro esquema moderno sigue rechazándose con
   `HC_UNSUPPORTED_SCHEMA` exactamente como antes.
6. `protectionsV4()` nueva, solo para n19: mapa V4 completo (**24 claves**,
   a–x: accessMode, remoteProxyUnlocked, expiryEnabled, expiryTime,
   expiryRequiresAutomaticTime, hwidLockEnabled, hwids, loginHwidEnabled,
   loginHwidScheme, loginHwidAuthorizationRequired, legacyHwidEnabled,
   mobileDataOnly, blockRoot, legacyExtraProtectionEnabled,
   providerLockEnabled, providerCodes, providerMatchOperatorName,
   countryLockEnabled, countryCodes, blockApplicationsEnabled,
   blockedApplications, note, sshBannerAsNote, tunnelBanner) + expansión
   del banner anidado (`v→version`, `s→style`, `h→content`; solo si el
   banner es objeto JSON; si es string se deja tal cual, igual que Python).
   n15 mantiene EXACTAMENTE su mapa histórico de 13 claves; n11/n12/934
   no cambian.
7. `decryptParsed()`: `partKey` aplica `hc-config-part-v12` cuando
   `material.n15 || material.n19`; la selección de protecciones es
   `material.n19 ? protectionsV4(...) : protections(...)`.
8. `app_version`: `build==942 ? "8.1.5 (942)"` en la cadena moderna.

Contraseña/HWID: por los flujos internos C++ existentes (parámetros de
`decodeHttpCustom`; errores `PASSWORD_REQUIRED` / `HWID_REQUIRED` /
`HWID_PASSWORD_REQUIRED` / `AUTH_FAILED`). NO se importó ninguna función
de autenticación del script Python (`_parse_auth_inputs`,
`_extract_hwid_value`, ni su manejo en `run()`).

## 3. Hallazgo durante la verificación: el mapa V4 tiene 24 claves, no 25

El brief decía "mapa V4 completo (25 claves)". El conteo real es 24
(a–x; el mapa Python `V4_PROTECTION_KEY_MAP` también tiene 24 entradas).
Un primer borrador del C++ declaró el array con tamaño 25 y 24
inicializadores: el slot 25 quedaba en `{nullptr, nullptr}` y la
comparación `name == pair.first` con puntero nulo es comportamiento
indefinido — el harness hacía SIGSEGV con un fixture sintético cuya `g`
traía una clave desconocida (`z`), que recorría el mapa entero sin
encontrar coincidencia. Los archivos reales no lo disparaban porque todas
sus claves coinciden antes de llegar al slot nulo. Corregido a tamaño 24
y cubierto por un caso sintético con clave desconocida (ver RESULTS.md).
Lección: declarar el tamaño del array a partir del conteo real, y que los
fixtures sintéticos incluyan claves desconocidas.

## 4. Divergencia real sin arbitrar: la ruta n19 protegida

El script aprobado `hc942_banner.py` y el codec de la nube componen la
clave protegida de forma DISTINTA, y ninguna de las dos está verificada
con una apertura real con contraseña correcta:

- **Nube (`codec.py::_derive_n19`, la que sigue este port):**
  `key = HKDF(fold_n19(aad) + passwordKey, seed, "hc-config-content-v14")`.
  La passwordKey se concatena ANTES del HKDF de contenido. Es el mismo
  patrón que `deriveN15()` del C++ (verificado con 934 reales).
- **Script (`hc942_banner.py::_section_material_934` + `_derive_n19`):**
  `contact = HKDF(fold_n19(aad), seed, "hc-config-content-v14")` (sin
  contraseña) y luego, si protegido,
  `contact = HKDF(contact + argon2id(...), seed, "app-config|n19|…")`
  con el info de `app-config|n19|features|build`. Es decir: HKDF de
  contenido primero y un SEGUNDO HKDF con etiqueta distinta después.
  El mismo patrón divergente aparece en su `_derive_n15`, mientras el
  C++/nube n15 usa fold+password-antes-del-HKDF.

Los 2 archivos 942 reales que abren son h=0 (sin contraseña), así que
ambas composiciones coinciden en lo verificado. La evidencia negativa sí
coincide en ambas: sin contraseña → `PASSWORD_REQUIRED`; con contraseña
incorrecta → `AUTH_FAILED`. La única forma de arbitrar es abrir el
archivo real protegido con su contraseña correcta. Este port sigue el
codec de la nube por instrucción expresa del encargo. Si esa apertura
demuestra que la composición del script es la correcta, `deriveN19()`
debe cambiarse a: HKDF-v14 sin contraseña + segundo HKDF con
`app-config|n19|…` cuando esté protegido (y habría que revisar si el
mismo cambio aplica a `deriveN15()` protegido, que hoy sigue el patrón
nube).

## 5. Alcance y límites

- Solo el port C++ del decoder. Sin push, sin APK, sin cambios en UI
  (Kotlin), CMakeLists ni `android/` — no hizo falta: el entry point y
  los errores ya existían y la UI offline ya gestiona
  `PASSWORD_REQUIRED`.
- Sin Gradle/NDK en esta VM: verificación solo host-side (ver RESULTS.md).
- n16/n17/n18/b=9 siguen rechazados por diseño.
- El banner de archivos 934 (n15) sigue sin expandirse por decisión de
  alcance (n15 byte-idéntico).

## 6. Auditoría HMAC (§2.2 de la política)

- Archivo/catálogo: las etiquetas AEAD XChaCha20-Poly1305 autentican
  sobre exterior, sección main, perfiles, capa HPR1 y sidecars; la clave
  de contenido n19 pasa por los prestates HMAC-SHA-256. Observado y
  verificado contra archivos reales.
- Transporte VPN: NOT_OBSERVED (no se ejercitó ningún transporte).
- Autenticación de conexión: NOT_OBSERVED (sin conexión ni verificador).
