# HTTP Custom 8.1.5 (build 942) vs 8.0.22 Patch 2 (build 934) — diff Java/DEX

- **Fecha del análisis:** 2026-11-24
- **Alcance:** solo lectura y análisis estático. No se modificó el repo ni se hizo push.
- **APK nueva:** `~/workspace/http-custom-update/hc815/work/apks/base.apk`
  - paquete `xyz.easypro.httpcustom`, versión `8.1.5`, `versionCode 942`
  - SHA-256: `d99b06748427872f12c6677fcf7a067460912e0008b2f1c66053244af48d33bf`
  - 5 DEX: `classes.dex`–`classes5.dex` (4.231.676 / 3.426.072 / 3.384.540 / 542.808 / 108.960 bytes)
- **Línea base 934:** `~/workspace/http-custom-update/apk/base.apk`, descompilado previo en
  `~/workspace/http-custom-update/jadx-out/` (manifest verificado en este trabajo:
  `versionCode="934"`, `versionName="8.0.22 - Patch 2"`).
- **Herramientas:** jadx 1.5.3 (`~/workspace/http-custom-update/jadx-1.5.3/bin/jadx`),
  androguard 4.1.4 (`~/workspace/http-custom-update/venv/bin/python`).
  Nota: `java` no está en el PATH de esta VM; jadx se ejecutó con
  `JAVA_HOME=$HOME/jdk21` (Temurin 21.0.13). Misma versión de jadx que la línea base.

## 1. Descompilación 8.1.5 (tarea 1)

- Comando: `jadx -d hc815/work/jadx-out hc815/work/apks/base.apk` (sin opciones
  adicionales, igual que la corrida base cuyo log es `~/workspace/http-custom-update/jadx.log`).
  Log de esta corrida: `hc815/work/jadx815.log`.
- Resultado: **13.620 archivos `.java`** en `hc815/work/jadx-out/sources/`
  (14.225 archivos en total), **`ERROR - finished with errors, count: 56`**.
  Línea base: 13.411 `.java` (14.013 archivos), 54 errores. El log de jadx solo
  registra el conteo, no la lista de archivos con error, en ambas corridas, por lo
  que no se puede afirmar qué clases fallaron en cada una; los conteos son
  comparables (54 → 56).
- jadx terminó con exit=1 por los errores de decompilación (mismo comportamiento
  que la corrida base); la salida es completa y utilizable. **No hizo falta
  recurrir a androguard como sustituto de jadx**, aunque androguard se usó para
  toda la comparación a nivel DEX (§3, §5).

## 2. Inventario de clases: qué cambió en nombres

- Clases DEX totales (androguard): **14.370 (934) → 14.654 (815), +284**.
  Métodos totales: 71.585 → 73.042 (+1.457). Métodos `native`: 19.839 → 20.752 (+913).
- Archivos `.java` jadx: 13.411 → 13.620 (+209).
- **Advertencia metodológica (importante):** el paquete `dev/epro/r0/` (la mayor
  parte de la lógica de la app) usa nombres ofuscados **re-aleatorizados en cada
  build**: 0 nombres de archivo `r0` coinciden entre 934 y 815
  (`comm -12` sobre las listas de archivos = 0 en `dev/epro/r0/`), y las listas
  difieren en 11.284 / 11.493 archivos solo por renombrado. Por tanto, el diff
  por nombre de archivo **no sirve** para `r0`; la comparación válida es a nivel
  DEX por descriptores (§3) y por archivos con nombre estable (§4).
- Fuera de `r0`, solo 7 rutas desaparecen y 11 aparecen, y casi todas son la
  misma clase sintética con otro sufijo aleatorio:
  - `Z11244019023321623390` (934) → `P11674755437939094346` (815): compañero
    sintético de `ProfileDatabase`, `CatalogRefreshReceiver`, `AssistDroid`,
    `CustomVpnService`, `VpnWatchdogJobService`, `androidx/sqlite/db`,
    `org/chromium/net`. Mismo papel, nuevo nombre aleatorio.
  - `Y6921797927338498306` (934) → `U8103346559052134363` (815): mismo patrón.
  - `o/bwmna/gdrqkg/izmyclvb.java` (934) → `h/prnup/fnruxh/szepgyrk.java` (815):
    el helper de strings cifrados (ver §6).
  - `com/pairip/licensecheck/LicenseClient$$ExternalSyntheticLambda0` →
    `...Lambda18` (renombrado de lambda sintética).
  - `com/google/android/material/bottomsheet/zJb/...` (815): ruta nueva por
    renombrado interno de la librería Material, sin cambio funcional visible.
- **Clases genuinamente nuevas en 8.1.5 (ruta estable, no renombrado):**
  1. `dev/epro/httpcustom/service/ConnectionTileService.java` — `TileService`
     (Quick Settings). Métodos: `onClick`, `onStartListening`, `onDestroy`,
     todos `native`. Declarado 3 veces en `resources/AndroidManifest.xml`
     (0 menciones en el manifest 934).
  2. `dev/epro/httpcustom/core/shortcuts/LauncherShortcutActivity.java` —
     `Activity` de atajo de lanzador (`onCreate`/`onNewIntent`, `native`).
     Con 2 compañeros sintéticos `P11674755437939094346` /
     `U8103346559052134363` en `core/shortcuts/`.
  3. `dev/epro/httpcustom/ui/ConnectionControlActivity.java` — Activity Compose
     de control de conexión, con ~15 clases sintéticas `$...` (lambdas Compose).
  4. Clases sintéticas nuevas asociadas a las anteriores
     (`CustomVpnService$P11674755437939094346` con métodos `a/b/c` que construyen
     `Intent` con `(Context, String, String, int, String, String, String, String)`,
     etc.). Son andamiaje de las 3 features nuevas, no cripto.
- **Ninguna clase con nombre estable desaparece** en 8.1.5. No hay clases nuevas
  de cripto, config ni exportación con nombre legible.

## 3. Comparación a nivel DEX por descriptores (evidencia fuerte, inmune al renombrado)

Script: `/tmp/dexcmp.py` (androguard `DEX`, sin xrefs). Para cada clase se comparó
el multiconjunto de `(descriptor de método, is_native)` y el nº de instrucciones
de cada método. Resultados para `Ldev/epro/httpcustom/`, `Ldev/epro/go/`,
`Ldev/epro/mobile/`:

| Clase | Veredicto |
|---|---|
| `HTTPCustomApp` | **IDÉNTICA** (descriptores + nº instrucciones) |
| `MainFactory` | **IDÉNTICA** |
| `SyncProvider` | **IDÉNTICA** |
| `core/util/CatalogRefreshReceiver` | **IDÉNTICA** |
| `feature/ipfinder/assist/AssistDroid` | **IDÉNTICA** |
| `feature/ipfinder/assist/AssistDroidSessionService` | **IDÉNTICA** |
| `protocol/ssh/HcrNativeCodec` | **IDÉNTICA** |
| `go/Seq`, `go/Universe`, `go/error` (+ 9 internas) | **IDÉNTICAS** (12/12) |
| `mobile/Mobile`, `mobile/ClientSession`, `mobile/RetryHandler`, `mobile/DestinationObserver`, `mobile/FileDescriptorProtector` (+ 3 proxies) | **IDÉNTICAS** (8/8) |
| `MainActivity` | misma forma; los descriptores "cambian" solo porque los tipos de retorno referencian clases `r0` renombradas (`P498210555524299422` → `D1580818960552665899`, etc.). Nº de métodos y formas no-`r0` idénticos. |
| `data/local/ProfileDatabase`, `ProfileDatabase_Impl` | ídem: solo renombrado de tipos `r0` en descriptores; nº de métodos y formas idénticos. `ProfileDatabase_Impl` no contiene literales string en ninguna de las dos builds. |
| `service/CustomVpnService` | ídem: 30 métodos en ambas; las diferencias de descriptor son solo tipos `r0` renombrados. |
| `service/VpnWatchdogJobService` | ídem: solo tipos `r0` renombrados. |
| `protocol/shared/slowdns/SlowDns` | **+1 método nativo** (ver §4). Resto idéntico. |

## 4. HcrNativeCodec y transform — SIN CAMBIO

`hc815/work/jadx-out/sources/dev/epro/httpcustom/protocol/ssh/HcrNativeCodec.java`
vs `jadx-out/sources/dev/epro/httpcustom/protocol/ssh/HcrNativeCodec.java`:
diff completo (únicas diferencias: renombrado ofuscado):

```diff
- import o.bwmna.gdrqkg.izmyclvb;
+ import h.prnup.fnruxh.szepgyrk;
-        izmyclvb.oeynnivvrnts0(1141);
+        szepgyrk.longktebfdic0(1205);
-                iOjrxijvrgaxo = ojrxijvrgaxo(objArr);
+                iCqbcgozgkzmi = cqbcgozgkzmi(objArr);
-    private native void hklyyjnormys();
+    private native void bikgltrptyrn();
-    private static native int ojrxijvrgaxo(Object[] objArr);
+    private static native int cqbcgozgkzmi(Object[] objArr);
     public static final native boolean transform(byte[] bArr, byte[] bArr2, int i, long j, boolean z, int i2);
```

- **Firma `transform` sin cambio:** `transform([B [B I J Z I)Z`, `public static final native`,
  idéntica en ambas builds (verificado también a nivel DEX: es uno de los
  exactamente 2 métodos llamados `transform` en cada APK — el otro es
  `com.trilead.ssh2.crypto.digest.MD5.transform([B I)V`, no relacionado).
- A nivel DEX, `HcrNativeCodec` es **IDÉNTICA** (descriptores + nº de
  instrucciones de cada método).
- **Sin llamadores Java:** `grep -rln "HcrNativeCodec"` sobre ambos `jadx-out`
  solo encuentra el propio `HcrNativeCodec.java` en cada build. Ninguna clase
  Java invoca `HcrNativeCodec.transform(...)` en 934 ni en 815; la llamada
  proviene del lado nativo (o por reflexión no visible en el descompilado).
  Esto es igual en ambas builds: no hay nuevo llamador Java.
- La constante del dispatch en el `static {}` cambia 1141 → 1205. Es el índice
  en la tabla de strings cifrados del helper nativo (ver §6); cambia en TODAS
  las clases (p. ej. `SlowDns` 59 → 76, `MainFactory` 1215 → 1289,
  `SyncProvider` 1070 → 1129, `CustomVpnService` 628 → 786), consistente con
  re-indexado de la tabla de strings al añadir strings nuevos, **no** con un
  cambio semántico. No debe interpretarse como un nuevo esquema.

## 5. Búsqueda de literales (tarea 3)

Búsqueda doble: (a) `grep` sobre ambos `jadx-out/sources/`; (b) tabla de strings
de los 5 DEX de cada APK con androguard (`/tmp/dexstrings.py`, `/tmp/hclit.py`).
Totales de strings DEX: 52.309 (934) → 53.042 (815); el churn (~20.700 strings
distintas por lado) es casi todo identificadores ofuscados re-aleatorizados.

| Literal | DEX 934 | DEX 815 | jadx-out 815 | Veredicto |
|---|---|---|---|---|
| `HCCFG` | 0 | 0 | 0 archivos | ausente en ambas |
| `app-config` | 0 | 0 | 0 | ausente en ambas |
| `hc-config` | 0 | 0 | 0 | ausente en ambas |
| `hc-local-key` | 0 | 0 | 0 | ausente en ambas |
| `HcrNativeCodec` | 1 (descriptor de clase) | 1 (descriptor de clase) | 1 archivo (`protocol/ssh/HcrNativeCodec.java`) | sin cambio |
| `transform` | 15 | 15 | solo `path.transform(...)` (gráficos) y `HcrNativeCodec` | sin cambio; sin nuevo `transform` |
| `n15` | 3 | 4 | 84 archivos | ver nota abajo |
| `n16` | 4 | 5 | 137 archivos | ver nota abajo |
| `n17` | 4 | 7 | 49 archivos | ver nota abajo |
| `n18` | 3 | 3 | 69 archivos | ver nota abajo |
| `n19` | 3 | 4 | 3 archivos | ver nota abajo |
| `argon` / `Argon` | 0 | 0 | 0 | **sin Argon2 en Java** |
| `HKDF` | 0 | 0 | 0 | **sin HKDF en Java** |
| `ChaCha` | 20 | 20 | — | idéntico (strings de BouncyCastle; mismo conjunto) |
| `AES/GCM` | 2 | 2 | — | idéntico (`AES/GCM/NoPadding`, `AES/GCM-SIV/NoPadding`) |
| `GCM` | 43 | 43 | — | idéntico |
| `.hc` | 0 | 0 | — | sin literal de extensión en ningún DEX |
| `export` / `import` | 1 / 4 | 1 / 4 | — | idéntico, sin churn |
| `octet-stream` / `vnd.` | 1 / 1 | 1 / 1 | — | idéntico |
| `Extra Protection`, `extra_protection`, `Access ID`, `access_id`, `HWID` | 0 | 0 | — | ausentes en ambas |
| `hwid` | 0 | 1 | — | el único hit 815 es `dchwidrrdhfb`, identificador ofuscado aleatorio |

**Nota n15–n19: todos los hits son falsos positivos.** Con límite de palabra
(`"n1[56789]"`) hay **0** coincidencias en `sources/dev/` en ambas builds.
Los hits son: (a) `kotlin.Function15`–`Function19` (stdlib Kotlin);
(b) nombres ofuscados de métodos/clases nativos, p. ej. en 815
`n15720811488748983901`, `n193033753348397983`, `n16242024436722438403`
(`sources/dev/epro/r0/D12782359456473426284.java:54,66`, etc.) — el prefijo
`n15…`/`n19…` es parte del nombre aleatorio, no un esquema; (c) una cadena
Base64 larga idéntica en ambas builds (contiene `n17` por azar). **No hay
`n19`, ni `b=14`, ni ningún otro número de esquema nuevo en Java.**
Tampoco hay nuevas etiquetas KDF ni nuevos campos de config visibles en Java:
los literales de config/exportación son idénticos entre builds.

**Nuevo cripto en Java: NO.** Sin Argon2, sin HKDF, sin ChaCha/AES-GCM nuevo
en código propio (los hits ChaCha/GCM son strings de BouncyCastle presentes
en ambas builds con el mismo conteo). `grep -riE "argon|hkdf"` en
`hc815/work/jadx-out/sources/dev/` = 0. `Cipher.getInstance` /
`SecretKeySpec` / `MessageDigest.getInstance` aparecen en `dev/epro/r0/` en
ambas builds (clases ofuscadas no comparables por nombre; ver §7, limitación).

## 6. Helper de strings cifrados (libf2c) — cambio menor

- 934: `sources/o/bwmna/gdrqkg/izmyclvb.java` (18 líneas).
- 815: `sources/h/prnup/fnruxh/szepgyrk.java` (20 líneas).
- Ambas hacen `System.loadLibrary("f2c")` en el `static {}`.
- 934, 5 métodos nativos: `dpqpjfpoanwt1`, `oeynnivvrnts0`, `qbtpmwoxbgtw3`,
  `qgayjvbiagej2` (todos `void(int)`, sufijos 0–3) + `sb250e956f549(int): String`
  (desencriptado de string por índice).
- 815, **6 métodos nativos**: `longktebfdic0`, `nymwnkzmmdji3`, `quqlxwmvimzd4`,
  `spuvnvbaetzd2`, `sztkyenenhhg1` (todos `void(int)`, sufijos 0–4) +
  `sd27913e872c5(int): String`.
- **Cambio real pero no cripto:** aparece un quinto slot de dispatch `void(int)`
  (sufijo 4: `quqlxwmvimzd4`). Es la superficie de dispatch Java→nativo para
  las nuevas features (las 3 clases nuevas usan `szepgyrk.longktebfdic0(...)`
  en sus `static {}`), no una nueva KDF. El método `String(int)` de
  desencriptado sigue siendo uno solo, con la misma forma.

## 7. Cambios reales encontrados (resumen de lo que SÍ cambió en Java)

1. **3 features de UI, todas con implementación `native`:**
   `ConnectionTileService` (Quick Settings), `LauncherShortcutActivity`
   (atajo de lanzador) y `ConnectionControlActivity` (pantalla de control de
   conexión). Ninguna toca cripto/config/exportación.
2. **SlowDNS: 1 método nativo nuevo** en
   `dev/epro/httpcustom/protocol/shared/slowdns/SlowDns.java` (diff completo
   en §4-analogía; el resto del archivo son solo renombrados):
   `public final native boolean takeStartupTimeout$app(String str, String str2);`
   (a nivel DEX: descriptor nuevo `(Ljava/lang/String; Ljava/lang/String;)Z`).
   Correlato en recursos: string nuevo `log_slowdns_startup_timeout`
   = "SlowDNS: Timed out while opening a session".
3. **Recursos `res/values/strings.xml`: 1.941 → 1.960 entradas (+19).** Nuevas:
   - Diagnóstico de errores: `error_reason_payload_local_request`,
     `error_reason_payload_relay`, `error_reason_payload_remote_connect`,
     `error_reason_payload_request_setup`, `error_reason_payload_tls_setup`;
     `error_stage_prepare_configuration`, `error_stage_prepare_transport`,
     `error_stage_start_local_proxy`, `error_stage_start_tunnel`.
   - Logs SlowDNS: `log_slowdns_calibration_largest_reply`,
     `log_slowdns_local_resolver_blocked`, `log_slowdns_mode_automatic_active`,
     `log_slowdns_qname_limit_too_small`, `log_slowdns_server_auth_failed`,
     `log_slowdns_startup_timeout`.
   - `shortcut_connection_requires_app` = "Open HTTP Custom to continue connecting."
   - Modos/tipos SlowDNS: `slow_dns_mode_ft_compact` ("FT Compact"),
     `slow_dns_mode_ft_standard`, `slowdns_type_ft` ("FT"),
     `slowdns_type_https` (valor literal "RX"), `slowdns_type_short_txt`,
     `slowdns_type_svcb`, `slowdns_short_txt_description`,
     `slowdns_default_or_range_error`.
   - Eliminadas: `slowdns_edns_range_error` (sustituida por
     `slowdns_default_or_range_error`), `slowdns_type_cname`,
     `slowdns_type_mx`, `slowdns_type_ns`, `slowdns_type_srv`.
   - No hay strings nuevos de exportación `.hc`, contraseña, HWID, operador,
     root ni Access ID.
4. **Strings DEX nuevos no-cripto:** `enable_lock_screen_ad`,
   `is_custom_close_blocked`, `network_ping_config`, `offline_ad_config`,
   `swipeable_interstitial_ad_config`, `throttle_configuration`
   (publicidad/config de red; el resto del churn es renombrado ofuscado).
5. **Crecimiento general:** +284 clases DEX, +1.457 métodos, +913 métodos
   `native` (la mayoría en `r0` y librerías actualizadas, no atribuible por
   nombre a una feature concreta).

## 8. Contexto nativo (fuera del alcance Java, solo inventario)

Mismo inventario de 11 `.so` en `split_config.arm64_v8a.apk` en ambas builds.
Tamaños (934 → 815):

| .so | 934 | 815 |
|---|---|---|
| `libaio.so` | 42.633.928 | 42.854.056 (+220.128) |
| `libf2c.so` | 15.562.432 | 16.117.312 (+554.880) |
| `libruntime.so` | 6.797.136 | 6.927.912 (+130.776) |
| `libcodec.so` | 114.504 | 109.872 (−4.632) |
| `libpolicy.so` | 236.696 | 230.648 (−6.048) |
| `libhev-socks5-tunnel.so`, `liblitevpn.so`, `libsqlcipher.so`, `libtun2socks.so`, `libdatastore_shared_counter.so`, `libandroidx.graphics.path.so` | idénticos en tamaño | idénticos en tamaño |

`libf2c.so` / `libruntime.so` / `libaio.so` crecieron; el cambio (si lo hay) en la
KDF interior n15–n18 estaría ahí, no en Java. No se analizó el nativo en este
trabajo. Tamaño idéntico no prueba contenido idéntico.

## 9. Qué NO cambió (con evidencia)

- **HcrNativeCodec / transform:** firma idéntica `([B [B I J Z I)Z`; clase
  IDÉNTICA a nivel DEX (descriptores + nº de instrucciones); diff de fuente
  solo renombrado; sin llamadores Java nuevos ni antiguos (§4).
- **Puente Go (`dev/epro/go`, `dev/epro/mobile`):** 20/20 clases IDÉNTICAS
  a nivel DEX (§3). `Mobile.runConfig/startConfig`, `ClientSession`,
  `Seq` (lib `aio`) sin cambio.
- **App principal:** `HTTPCustomApp`, `MainFactory`, `SyncProvider`,
  `CatalogRefreshReceiver`, `AssistDroid` (+ servicio) IDÉNTICOS a nivel DEX.
- **Sin nuevo esquema:** no hay `n19`, `b=14` ni otro valor de `b`/`e`, ni
  etiquetas `HCCFG`/`app-config`/`hc-config`/`hc-local-key` en ningún DEX ni
  en el Java descompilado, en ninguna de las dos builds (§5).
- **Sin nuevo cripto Java:** sin Argon2, sin HKDF, sin ChaCha/AES-GCM nuevo
  en código propio (§5).
- **Exportar/importar `.hc` y bloqueos:** sin evidencia de cambio en Java.
  Literales `.hc`, `export`, `import`, `octet-stream`, `vnd.` con conteo
  idéntico y churn 0; sin literales de contraseña/HWID/operador/root/
  Access ID/Extra Protection en ningún DEX (§5). La lógica de importación
  vive en `dev/epro/r0/` (no comparable por nombre), pero no hay ningún
  indicador Java/DEX de un cambio en ese flujo.
- **Nuevos campos en la config:** ninguno visible en Java. Los únicos campos
  nuevos visibles son de SlowDNS en recursos (modos FT, tipos FT/HTTPS/
  short_txt/SVCB) y de diagnóstico; no son campos de la config `.hc`.

## 10. Limitaciones

- El grueso de la lógica (`dev/epro/r0/`, ~11.300 clases) no se puede
  comparar archivo a archivo porque el ofuscador re-aleatoriza todos los
  nombres en cada build. La conclusión de "sin cambio en lo cripto" se apoya
  en: (a) `HcrNativeCodec` byte-equivalente en estructura DEX; (b) puente
  Go/mobile y clases principales IDÉNTICAS; (c) conjuntos de literales
  cripto/config idénticos en DEX; (d) cero llamadores Java nuevos de
  `transform`. Un cambio dentro de una clase `r0` concreta (p. ej. en el
  flujo de importar `.hc`) no se puede descartar solo con este método, pero
  no hay ningún indicador de ello.
- Los strings sensibles van cifrados por índice vía `libf2c.so` (`sd27913e872c5`),
  así que su ausencia en la tabla de strings DEX no prueba su ausencia en el
  binario; las etiquetas KDF nuevas, si existen, seguirían estando en el
  nativo, como en 934.
- jadx deja 56 errores (54 en la base); el log no lista los archivos
  afectados, así que alguna clase podría estar incompleta en el descompilado
  sin que se detecte aquí. Las clases citadas en este informe se verificaron
  presentes y legibles en ambas salidas.

## 11. Implicación para SP-DECODE (propuesto, no implementado)

- **El bloqueo de la KDF interior n15–n18 sigue en el nativo**, igual que en
  934: el Java 8.1.5 no aporta ninguna etiqueta, esquema ni primitiva nueva
  que lo desbloquee. No hay nada nuevo que integrar desde Java para
  n15–n18, y no hay evidencia de un n19 que obligue a ampliar el soporte.
- Lo único que podría afectar a futuros archivos `.hc` son los nuevos
  modos/tipos SlowDNS (FT, HTTPS/"RX", short_txt, SVCB) y el timeout de
  inicio de sesión SlowDNS: si un `.hc` de 8.1.5 usa esos modos, el
  decodificador Python deberá contemplarlos cuando aparezca una muestra real.
  Esto es una hipótesis a verificar con un archivo real, no un hallazgo.
- Archivos generados: este informe
  (`~/workspace/http-custom-update/hc815/work/java-diff.md`),
  descompilado 8.1.5 en `~/workspace/http-custom-update/hc815/work/jadx-out/`,
  log `hc815/work/jadx815.log`. Scripts de comparación (efímeros, en `/tmp`):
  `dexstrings.py`, `dexcmp.py`, `hclit.py` con salidas en
  `/tmp/dexstrings.out`, `/tmp/dexcmp.out`.
