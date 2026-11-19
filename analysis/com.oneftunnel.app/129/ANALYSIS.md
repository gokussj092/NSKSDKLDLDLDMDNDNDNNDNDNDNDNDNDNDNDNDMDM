# 1FTunnel 0.7.3 (build 129) — revisión de método y del archivo real

Estado: **PARTIAL**. El formato 0.7.3 es idéntico al 0.7.1; el archivo real de
Pedro abre con el decodificador del repo (CLI) pero **la ruta del worker del
servidor lo rechaza** (codec.py desactualizado). Sin puerto offline: el
propietario eligió ONLINE ONLY el 2026-11-19.

## 1. Objetivo

Pedro envió el 2026-11-19 ~00:24 un archivo `Free-23_0_jn8j.1ftnl` (1.690 B)
que no abría, junto con la APK 1FTunnel v0.7.3, y preguntó si se había
actualizado y, si no, por qué no se abre la configuración. También confirmó
que la APK offline f75c6751 pasó sus pruebas. Esta revisión responde:
por qué no abre, si 0.7.3 cambió el método, y si el servidor la abriría.

## 2. Muestras (hashes; los archivos no están en Git)

| Muestra | Tamaño | SHA-256 |
|---|---:|---|
| 1FTunnel-v0.7.3 APK (owner) | 36.893.068 | `5f7a58aabfe4350f776b7d20e3116659fb50552952358d46818edfa77bb329c5` |
| Free-23_0_jn8j.1ftnl (owner) | 1.690 | `4717f7074b63236aefaf2c4f70f8525f59e44da3d4b3aa08625e733322bbd002` |
| 1FTunnel 0.7.1 APK (trabajo previo) | 36.574.399 | `cf956f0ea45189e32bf1c5769b4977000d77cfe4b31a80db8ff67f77ed1c0ac1` |
| liboneftunnel-security.so arm64, 0.7.3 | 916.792 | `71216816f3416140abad45f3464b64bcf4d3d19b4f4536dcaa27d2df23dd0c93` |
| liboneftunnel-security.so arm64, 0.7.1 | 916.568 | `0c596ef5a1a5ed267a49a14c32fb517403f5d48014702101f6a425e181ee1038` |
| classes.dex 0.7.3 / 0.7.1 | 2.536.292 / 2.503.680 | `2490ff33…` / `3fe478b3…` |
| classes2.dex (ambas, idéntica) | 197.160 | `4b456639e17b165d8a0f3bc8f4682ad17bd14e1a46e2e41170ee3df53782adfd` |

APK 0.7.3 verificada con androguard: package `com.oneftunnel.app`,
versionName `0.7.3`, versionCode **129**, minSdk 24, targetSdk 36.
El expediente 0.7.1 es `analysis/com.oneftunnel.app/127/` (build 127).

## 3. El archivo real: qué es y por qué no abría

Estructura observada (solo estructura y códigos; ningún valor del perfil):

- Texto `1FTnl.`, 1.690 caracteres. Envelope binario 1.267 B tras reponer el
  magic `1FT1`: **versión 3**, algo 1, KDF 1, salt 16 B, nonce 12 B,
  AAD 122 B, ciphertext+tag 1.101 B (longitudes exactas, sin resto).
- AAD: package `com.oneftunnel.app`, certificado = primer fingerprint del
  decodificador, configVersion 1, **keySlot 1, minimumAppBuild 129**,
  createdAt 2026-11-18, expiry 2026-11-28, configType **SSH**,
  **lockMode 2 (contraseña)**, blockRoot True.
- Sin contraseña el decodificador del repo devuelve `PASSWORD_REQUIRED`
  (verificado). Eso es lo que Pedro veía: el perfil está protegido con
  contraseña y la app/servidor la pide; sin ella no hay apertura posible.
- Con la contraseña aportada por Pedro (usada solo vía variable de entorno,
  nunca guardada ni escrita en ningún informe), el archivo **abre completo**
  con `decoders/Python/apps/OneFTunnel/1FTunnel.py`:
  formato `1FT1`, `authenticated: True`, `isPartial: False`, configType SSH,
  **CFG1 v6**, secciones SSH sí / Inject sí (modo **SLOWDNS**) / DNS no /
  Xray no / **SlowDNS sí** (resolver, nameserver, publicKey, recordType),
  fieldLockMask 447, id y nombre no vacíos.
- Conclusión: **el archivo está bien; solo le faltaba la contraseña.**

## 4. 0.7.3 vs 0.7.1: el método NO cambió

Evidencia (todo observado, nada inferido):

1. **Prueba decisiva — el archivo real autentica con la clave 0.7.1.**
   El archivo fue exportado por 0.7.3 (minimumAppBuild 129 en el AAD) y su
   etiqueta AES-256-GCM verifica con el `ROOT_KEY` y las etiquetas
   `1FT1 password v2` / `1FT1 HKDF AES-256-GCM v2` del decodificador 0.7.1.
   Si 0.7.3 hubiera rotado la clave o la KDF, el GCM fallaría
   (`AUTH_FAILED`). No falló. La KDF nativa, el ROOT_KEY y las etiquetas son
   las mismas en 0.7.3.
2. **Librería nativa.** Ambas `.so` arm64 contienen exactamente el mismo
   conjunto de etiquetas KDF (`1FT1 password v1/v2`,
   `1FT1 HKDF AES-256-GCM v1/v2`; sin `v3`) y el mismo conjunto de 2.142
   strings significativos (diff vacío). La diferencia de tamaño es solo
   224 B (916.568 → 916.792) y los símbolos JNI se desplazaron +0x20/+0x90
   (decrypt 0x658d8 → 0x658f8, encrypt 0x62790 → 0x627b0): deriva de
   compilación, no un método nuevo. No hay slots nuevos en las etiquetas.
3. **DEX.** `classes2.dex` es byte-idéntica. En `classes.dex`, todas las
   clases `com.oneftunnel.app.*` son idénticas (mismos modelos:
   SlowDnsConfig, SlowDnsRecordType, InjectMode, ConfigType, XrayConfig,
   etc.); el único churn es de librerías androidx (lifecycle/datastore).
   Los valores de enum son idénticos: InjectMode 6 valores (incl.
   SLOWDNS), SlowDnsRecordType 9 valores (incl. A/AAAA), ConfigType 4,
   XrayProtocol 5. Los únicos tokens nuevos en 0.7.3 son mensajes de error
   de SlowDNS, los parámetros de enlace `slowdns`/`slowdnskey` y
   `active_load_balance_group_id`: superficie nueva de enlaces SlowDNS,
   no un cambio de contenedor. No hay CFG1 v7 (el máximo sigue siendo v6).
4. **Sin catálogo.** Como en 0.7.1, no hay endpoint de catálogo en el APK.

### Nota sobre el hash del .so en el expediente 0.6.99

El ANALYSIS.md de 0.6.99 registra la `.so` arm64 con SHA
`b46e8542…` (915.016 B). La APK 0.7.1 real contiene una `.so` distinta
(`0c596ef5…`, 916.568 B): ese hash es la `.so` de 0.6.99, y el oráculo
Unicorn (`scripts/apk_analysis/oneftunnel_native_oracle.py`) fija ese hash.
Por eso el oráculo **no** se re-ejecutó para 0.7.3: la prueba del archivo
real (punto 1) es más fuerte que la emulación, y re-fijar el oráculo a la
`.so` 0.7.3 exigiría localizar de nuevo la función KDF (las direcciones
fijas 0x6432c/0x6a7ec son de la `.so` 0.6.99). Queda registrado como
pendiente menor, no como bloqueo: la equivalencia KDF ya está probada por
el archivo real.

## 5. El servidor: cableado correcto, decodificador desactualizado

Verificado contra el head remoto `ci/unity-ads-online-qa` = `3e4a02c0`
(clon superficial HTTPS, 2026-11-19):

- **Cableado (correcto).** `supplied-integrations.json` (`/apps[29]`):
  id `oneftunnel`, package `com.oneftunnel.app`, versionCode 127,
  `catalogModule: 1FTunnel.py`, `fileModule: 1FTunnel_archivos.py`,
  extensiones `["1ftnl"]`, textPrefixes completos, `catalogState:
  USER_PROFILES_ONLY`. `text-formats.json` registra los prefijos
  `1ftunnel://1FTnl/`, `1ftunnel://1FT1/`, `1FTnl.`, `1FT1.`,
  `1ftunnel://locked-v2/`, `1ftunnel://locked/`, `1FTlb.` y `1ftunnel://`.
  El gateway (`c3-gateway.mjs:126,148,232`) enruta el formato `1ftnl` y los
  prefijos de texto; `decoder-client-compat.mjs` lista los mismos prefijos.
  `manifest.json` del proveedor: entrypoint `1FTunnel.py`, payloadVersions
  1–6, credentials `["password"]`, `realSampleVerified: true`.
- **Ruta del worker (el problema).** `supplied_bridge.py::file_decode`
  (líneas 341–345): para textos `1FTnl.`/`1FT1.`/`1ftunnel://…` llama a
  `file_decoder.run(raw, password)`; `file_decoder.py` importa
  `decode` de **`codec.py`**, un módulo dividido y desactualizado cuyo
  `parse_config` solo acepta `version in range(1, 6)` (CFG1 v1–v5).
  En cambio `1FTunnel.py` (autocontenido, entrypoint del manifest) acepta
  `range(1, 7)` (v1–v6 + SlowDNS) y `1FTunnel_archivos.py` también usa
  `1FTunnel.decode`.
- **Reproducido con el archivo real.** La ruta exacta del worker
  (`file_decoder.py --password-stdin`, contraseña correcta) devuelve
  **`UNSUPPORTED_PAYLOAD_VERSION`** (exit 1). Sin contraseña devuelve
  `PASSWORD_REQUIRED` (la comprobación de lockMode ocurre antes de
  descifrar). Es decir: **en la online, este archivo fallaría aunque se
  introduzca la contraseña correcta** — el error que vería el usuario no
  sería "contraseña incorrecta" sino un fallo de descodificación.
- **Matiz:** los archivos **binarios** `1FT1` v6 no toman esa rama: el
  router los envía a `1FTunnel_archivos.py` → `1FTunnel.decode`, que sí
  acepta v6. El fallo afecta solo a los archivos de **texto** (`.1ftnl`
  `1FTnl.`/`1FT1.`) con CFG1 v6, que es justo el formato que exporta la
  app (el archivo de Pedro es texto v6).
- **No se hizo prueba en vivo** contra el servidor desplegado desde esta
  VM (el transporte V2 exige autenticación de dispositivo/sesión); el
  veredicto es el código desplegado en el head remoto ejecutado
  localmente por la ruta exacta del worker. Una prueba en la app por parte
  del propietario lo confirmaría de extremo a extremo.

### Corrección propuesta (no aplicada; requiere decisión del propietario)

Alinear `codec.py::parse_config` con `1FTunnel.py` (aceptar CFG1 v1–v6 y
la sección SlowDNS) o hacer que `file_decoder.py` importe `decode` desde
`1FTunnel.py` en lugar de `codec.py`. Después, redesplegar el worker y
re-probar con un archivo v6 real. Es un cambio de una función, no un
método nuevo: el resto del cableado ya está en su sitio.

## 6. Por qué no abre en cada sitio (resumen)

| Sitio | ¿Abre este archivo? | Motivo |
|---|---|---|
| App 1FTunnel 0.7.3 (con contraseña) | Sí | Es su propio formato; lo exportó ella |
| SP-DECODE online (servidor, con contraseña) | **No** | `codec.py` rechaza CFG1 v6 (`UNSUPPORTED_PAYLOAD_VERSION`) |
| SP-DECODE online (sin contraseña) | No | `PASSWORD_REQUIRED` (correcto) |
| SP-DECODE offline | No | `.1ftnl` no está soportado; el propietario eligió ONLINE ONLY (2026-11-19), sin puerto |
| Repo decoder CLI `1FTunnel.py` (con contraseña) | Sí | Acepta CFG1 v1–v6; verificado con el archivo real |

## 7. HMAC / autenticación de conexión (§2.2)

`connection_authentication: UNCONFIRMED`. El AES-256-GCM del contenedor es
autenticidad del **archivo** (la etiqueta verifica que el perfil no fue
alterado y que la contraseña/KDF son correctas), no autenticación de la
conexión VPN. No se investigó HMAC de transporte ni de establecimiento de
conexión en esta revisión; igual que en el expediente 127.
