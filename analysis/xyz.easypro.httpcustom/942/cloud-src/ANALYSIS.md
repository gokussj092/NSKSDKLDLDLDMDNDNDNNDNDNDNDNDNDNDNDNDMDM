# HTTP Custom 8.1.5 (build 942) — nuevo esquema HCCFG 14/n19

- Fecha: 2026-11-23/24 (Tijuana).
- Paquete: xyz.easypro.httpcustom, versionName 8.1.5, versionCode 942,
  minSdk 32, targetSdk 36. Fuente: .apks enviado por Pedro.
  SHA-256 del .apks:
  `8d1c0af4b0b442b4d2d291f6a5d0da1d32f43407cded9e54700ef3062ea17ffa`
  (35,243,186 B; base.apk 13,316,047 B + split arm64 29,074,396 B + xhdpi 40,815 B).
- Archivos de prueba (3): `test_bloqueo_normal_con_contrase_a_0_m46a.hc`
  (4,981 B), `test_bloqueo_normal_1_aflj.hc` (4,935 B),
  `test_open_2_7xqg.hc` (4,529 B). Hashes en RESULTS.md y en
  `tools/hc-inventory.json`.
- Estado: **método nuevo IDENTIFICADO (b=14/n19) pero KDF interior NO
  recuperada**. Ningún archivo abre. Ver RESULTS.md.

## 1. Lo que cambió vs 934 (8.0.22 Patch 2, build 934)

### Formato de archivo — nuevo esquema
- Los 3 archivos son **HCCFG b=14 / e=n19, n=942** (verificado: el sobre
  exterior abre con `codec.py::open_envelope` y expone esos campos).
- Sin cambios de forma: `c=s1`, `d=h1`, `f=["ssh","profiles"]`, semilla `g`
  de 32 B, secciones `i` + 2 `j`. Sin campos nuevos en el sobre; ningún
  archivo trae cápsula `p` ni slots HWID `o` (en 934 esos solo estaban en
  n17/n18 y n16/n18).
- Protección: archivo 1 con contraseña (`h=1`, Argon2id `k=a1, l=2,
  m=67108864`, mismos parámetros que los n15 protegidos de 934); archivos
  2 y 3 sin contraseña (`h=0`). El archivo 2 se llama "bloqueo normal"
  pero el sobre dice h=0; sus longitudes de cifrado son idénticas a las
  del archivo 1 (mismo perfil exportado con y sin contraseña — observación
  de longitudes, no de contenido).
- **El sobre exterior HCX4-v4 sigue autenticando** con la misma clave que
  en 934 (derivada de `native_fold` del sello v4). El cambio está solo en
  el interior (n19).

### Java/DEX — sin cambio cripto
- Descompilado jadx 1.5.3: 13,620 .java, 56 errores (934: 13,411 / 54).
- `HcrNativeCodec.transform` IDÉNTICO a nivel DEX (firma
  `([B [B I J Z I)Z`, sin llamadores Java en ninguna build; la llamada
  viene del nativo). Puente Go/mobile y app principal IDÉNTICOS.
- Cambios reales, todos fuera de cripto/config: 3 features de UI con
  métodos `native` (`ConnectionTileService`, `LauncherShortcutActivity`,
  `ConnectionControlActivity`); 1 método nativo nuevo en SlowDNS
  (`takeStartupTimeout$app`); helper de strings cifrados con un quinto
  slot de dispatch; recursos SlowDNS nuevos (modos FT compact/standard,
  tipos FT, HTTPS "RX", short_txt, SVCB) y strings de diagnóstico.
- Sin literales `HCCFG`/`app-config`/`hc-config`/`hc-local-key` en ningún
  DEX (0 en ambas builds); `n15`–`n19` solo falsos positivos (Kotlin
  Function15–19, nombres ofuscados). Sin Argon2/HKDF/ChaCha/AES-GCM nuevo
  en Java. Detalle con evidencia en `tools/java-diff.md`.

### Nativo — la construcción interior cambió de nuevo
- `libruntime.so` 6,797,136 → 6,927,912 B (+1,92 %, SHA-256
  `f6a65f69cbb2296e…`); `libf2c.so` 15,562,432 → 16,117,312 B (+3,57 %,
  SHA-256 `6b65bd27…`). Corrección: el salto ~2× de libruntime fue
  884→934, no 934→8.1.5. 6 librerías sin cambio (mismo SHA-256).
- **Desaparecen `hc-config-content-v12` y `hc-local-key-capsule-v2`** de
  `libruntime.so`; solo sobrevive `hc-config-part-v12` (ahora en
  `0x277d4`). No hay etiquetas `v13`/`v14`, ni `HCCFG`, `app-config`,
  `n15`–`n19`, `libSRPatch`, `frida` ni `ro.*` en ningún `.so`.
- Prestates 899 INNER/OUTER ausentes (igual que 934). Tabla K SHA-256
  intacta byte a byte. Blob `.rodata` en torno al HMAC probable de 934
  (`0x263e38`) reescrito por completo, sin ancla estática.
- Trampa 0x88c: sin equivalente estático visible — pero el mismo escaneo
  da 0 en 934 (donde existe vía despachador VM), así que su ausencia no
  prueba que haya desaparecido.
- Detalle con evidencia en `tools/native-diff.md`.

## 2. Sonda de la KDF interior n19 — 0/35 (harness validado)

Herramienta: `tools/probe_n19.py`. Prueba construcciones candidatas
contra la sección `i` de `test_open_2_7xqg.hc` (h=0) con el tag
Poly1305 como oráculo. Control: la misma rejilla sobre
`drive/Test Oppen.hc` (934, n15, h=0) abre con la construcción n15
documentada en `codec.py::_derive_n15` (2/35, el duplicado es la misma
construcción) — el harness está validado.

Rejilla n19 (35 combinaciones, 0 aciertos):
- A: estilo n15 con sustituciones 14/n19/942 — folds {native_fold_n15,
  native_fold} × content-label {v12, v13, v14} × part-label {v12, v13,
  v14, directo}.
- B: estilo transcript n11/n12 con `app-config|n19|…` — folds {n15, v4}
  × part-label {v12, v13, v14, directo}.
- C: AAD con esquema viejo (12/n15 y 14/n15) y build 942.

Conclusión: la KDF interior n19 NO es la n15 con sustitución directa de
esquema/schedule/build/labels. Falta al menos un elemento desconocido:
nuevos prestates del fold (como los N15_INNER/OUTER lo fueron para n15),
un prefijo distinto de 0xf1, una etiqueta de contenido distinta de
v12/v13/v14, o un AAD/transcript con otra forma. Re-localizar el HMAC y
la trampa en el nativo 8.1.5 requiere emulación (fuera del alcance
estático; el camino 934/884 quedó bloqueado por la trampa 0x88c).

## 3. Precedente: cómo se resolvió n15 (y por qué n19 sigue cerrado)

La KDF interior n15 NO se recuperó por análisis estático ni por
emulación (1,044 combinaciones de rejilla en 934, 0 aciertos). Se
resolvió porque Pedro envió un script lector para 934
(`HttpCustomAllversion_0_r7t9.py`, ver dossier 934
`REVISION_N15_2026_11_16.md`), con la corrección de Codex en la rama
de contraseña. Los prestates N15_INNER/OUTER y el prefijo 0xf1 se
recuperaron del motor nativo de 934 a partir de ahí.

Para n19, las vías realistas son las mismas: (a) un script lector para
8.1.5, o (b) recuperar los nuevos prestates/etiquetas del motor nativo
de 8.1.5 (emulación; bloqueada por la misma trampa que en 934/884).
No se probaron contraseñas ni variantes de contraseña en este trabajo
(prohibido); el archivo 1 queda PENDING también por falta de contraseña.

## 4. Limitaciones
- La comparación Java no puede descartar un cambio dentro de una clase
  `dev/epro/r0/` concreta (nombres re-aleatorizados por build); no hay
  ningún indicador de ello (literales y descriptores idénticos).
- La sonda cubre solo construcciones derivadas de la n15/n11
  documentadas. No cubre prestates nuevos ni etiquetas no literales.
- No se tocó el repo (`decoders/Python/HTTPCUSTOM.py` sin cambios, sin
  commit ni push). El decodificador actual rechaza los 3 archivos con
  `UNSUPPORTED_SCHEMA` (verificado).
- No hay credenciales, contraseñas, HWIDs, contenido descifrado ni
  nombres reales en este expediente.

## 4. Resolución — fusión n19 (2026-11-26)

La KDF interior n19 se recuperó por la vía del precedente n15: el script
lector para 8.1.5 (`tools/hc942_banner.py`, aprobado 2026-11-26, con el
`tunnelBanner` anidado arreglado). Los estados N19_IPAD/OPAD y la
derivación `_derive_n19` (HKDF `hc-config-content-v14`, prefijo 0xf1, mismo
digest de certificado que n15) son la pieza que faltaba; la sonda 0/35 de
la sección 2 falló porque probaba los prestates n15/v4, no los n19.

**Punto exacto de fusión:** el motor moderno
`decoders/Python/apps/HTTP_Custom/codec.py` + `crypto.py` — NO
`_hc_hccfg.py` (ese archivo solo cubre los esquemas históricos b=1–7,
n1/n2/n7/n8; el soporte 934/n15 vive en `codec.py`, y `HTTPCUSTOM.run` y
`cloud/workers/python/hc_bridge.py` intentan el motor moderno primero).
Cambios: `N19_INNER/OUTER_STATE` + `native_fold_n19()` en `crypto.py`;
`_derive_n19()`, despacho b=14/e=n19, `_skey` con `hc-config-part-v12`
también para n19, `app_version` "8.1.5 (942)", y `V4_PROTECTION_KEY_MAP` +
`BANNER_KEY_MAP` con expansión del `tunnelBanner` solo para n19 (n15 se
mantuvo byte-idéntico; ver pendiente 3 en `tools/VERIFICATION_2026_11_26.md`).

**Regla de contraseña/HWID (Pedro, 2026-11-26):** NO se importaron
`_parse_auth_inputs`, `_extract_hwid_value` ni el manejo de
contraseña/HWID de `run()` del script nuevo. La credencial sigue por las
funciones internas existentes (`_parse_auth`, taxonomía `HCError`
`PASSWORD_REQUIRED` / `HWID_REQUIRED` / `HWID_PASSWORD_REQUIRED` /
`AUTH_FAILED`) y el flujo de credenciales pendientes del bot. Ningún caso
sin cubrir detectado.

**Estado tras la fusión:** 2/3 archivos abren (los 2 sin contraseña, 2
perfiles c/u, banner expandido); el archivo con contraseña requiere la
credencial (`PASSWORD_REQUIRED`; con contraseña incorrecta `AUTH_FAILED`).
n16 sigue cerrado, Gjost sigue pidiendo HWID, 884 sigue sin ser sobre 934.
Evidencia completa en `tools/VERIFICATION_2026_11_26.md`.
