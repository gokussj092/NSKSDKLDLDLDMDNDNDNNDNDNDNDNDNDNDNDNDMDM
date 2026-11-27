# XtraVPN — revisión de conexión + re-verificación 2026-11-27

Estado: PARTIAL. Se conecta código aportado sin modificar su algoritmo ni atribuir una descarga remota nueva.

Registro detallado: [ANALYSIS.md](../../platform/supplied-integrations/2026-11-14/ANALYSIS.md).

Fuente y límites originales: [XtraVPN](../../../decoders/Python/apps/XtraVPN/README.md).

Reproducir la comprobación de importación y binding, sin red:

```bash
python analysis/platform/supplied-integrations/2026-11-14/tools/verify_provider.py xtravpn
```

Las pruebas de broker, worker aislado y regresión se ejecutan desde el expediente compartido. Las muestras faltantes y bloqueos se mantienen explícitos; esta comprobación no certifica al proveedor.

---

## Re-verificación 2026-11-27 (lote 15, app 8 de 8)

App XtraVPN 1.0.36 (versionCode 62), package `com.xtravpn.dev`.
APK `XtraVPN_1.0.36_12_tlco.apks`, SHA-256
`6faf94e447ea06987143988aeb8f3822e652097acffc1dfd77b5230e66ad05d3`.

**El APK es el mismo que el analizado el 2026-11-13:** `classes.dex`
SHA-256 `7ec8f8b4440d70dfd09e858d35106c4d3d099f2a97fc59febd2bc782ad238709`
(byte-idéntico), asset `assets/config/config.json` idéntico (3,612
bytes, SHA-256 `3543c5b8…`), certificado de firma idéntico (SHA-256
`0724df38…`). Librerías nativas todas en el split arm64
(`libgojni.so` xray-core, `libxray.so`, `libfarikudp.so`, `libdns.so`,
`libdnstt.so`, `libpdnsd.so`, `libtun2socks.so`, `libconscrypt_jni.so`,
`libpl_droidsonroids_gif.so`); el catálogo es Java puro.

### Tres correcciones al análisis del 2026-11-13 (verificadas en smali de ESTE dex)

1. **Hay UNA sola clave de catálogo, `Pitingo2089`, para todo** (asset,
   Config.json descargado y textos pegados). El README previo decía que
   el camino remoto usaba el ID de AdMob
   (`ca-app-pub-1778627428199734/4229593543`) como clave B0. Es al revés:
   en `XtravpnMainActivity.<clinit>`, `B0 = new Sk(17).toString()` y
   `Sk(17)` emula a `Pitingo2089`; `ServersActivity.I = new hj(6).toString()`
   = `Pitingo2089`; `Ld2.run` descifra el cuerpo descargado con
   `uW.i(body, B0)` en los dos caminos (Lyj ~línea 523 y LAK ~línea 731).
   El ID de AdMob es `A0 = new hj(17).toString()`, un ad unit, **no** una
   clave de catálogo. El script lo mantiene solo como segundo intento
   heredado e informa qué clave abrió el config.
2. **Timeout de descarga: 10 000 ms, no 5 000 ms** (`const/16 10000` en
   `Lv0.run()`; GET plano con `HttpURLConnection`, sin cabeceras propias).
   (El script de integración usa 30 s de timeout propio; el cambio es
   documental respecto al comportamiento de la app.)
3. **`xtravpn://` SÍ existe como texto pegado.** El README previo decía
   que no había esquema propio. No hay deep link en el manifest (ningún
   intent-filter con ese scheme), pero el diálogo de pegar
   (`XtravpnMainActivity.x()`) acepta texto que empiece por `xtravpn://`
   (quita los 10 primeros caracteres) o el blob cifrado tal cual, lo
   descifra con B0 y lo instala si es JSON con `Servers` y versión más
   nueva. El script lo reproduce con `--text`.

4. **La clave fija `23605c1568999d3a` SÍ funciona** (el README previo
   decía que estaba muerta: "12 bytes after Base64 and cannot decrypt").
   En `p()`, si el Android ID no abre el custom code, se reintenta con
   esta clave (construida en `p()` con 16 constantes `int-to-byte`; NO
   es un literal en el dex — verificado por emulación). Verificado en
   este patch con un código sintético cifrado con esa clave: abre y
   devuelve la URL.

Sin cambios: envoltorio exterior Base64 → XXTEA modificado (delta
`0xF5D09E4D`, palabras little-endian, última palabra = longitud),
claves de campo r55–r58, K9.h (alfabeto `:;<=>?!"#$%&'()*`, AES-256-CBC,
clave = SHA-256 del hex en mayúsculas, IV cero), César −1 en letras,
Vj0.h (AES-128-ECB, clave = primeros 16 bytes, Base64), derivación de
la contraseña SSH Sp0.g (SHA-256, 16 hex, rota cada hora UTC).

### Asset verificado

El asset abre con `Pitingo2089`: Version **1.0.0**, ReleaseNotes
`1.0.0😀`, **1 servidor** ("Tigo Panamá. Op-1", FLAG `pa`,
ServerPort 80, SSLPort 443, isDirect). ServerIP → `unpkg.com`
(hostname); ServerUser → `tipaop1`; Payload → texto HTTP legible;
SNI → `abc.greenp.site`. Self-test del script: **8/8 OK**.

### Catálogo en vivo — VERIFIED_REAL, pero sin broker posible

La pantalla **Acerca de** lo explica ("Servidores por token"): el
"token" es el Android ID (botón con ícono de huella → lo copia al
portapapeles); el usuario lo comparte con el proveedor/admin, que
devuelve un "código de servidores" (texto Base64 = la URL del catálogo
cifrada con AES-128-ECB, clave = primeros 16 bytes del Android ID).
El usuario lo pega en el diálogo "Pega tu clave o lista" (`p()`:
primero Android ID, luego la clave fija); la app guarda el código en
`SharedPreferences "AppPreferences" → "customCode"` y descarga con GET
plano (10 s), descifra con `Pitingo2089`, y guarda si la versión es
más nueva.

**No hay URL pública ni URL fija en la app.** La URL solo existe
dentro del código personalizado, y ese código solo se abre con el
Android ID del teléfono (o con la clave fija, si el proveedor usó esa).
Por eso **no hay broker posible** y `catalogState` se mantiene en
`CUSTOM_CODE_URL_REQUIRED`. No se inventó ninguna URL.

El catálogo en vivo **v5.4.675, 178 servidores**, fue verificado desde
el `Config.json` descargado por la app en el teléfono (abre con
`Pitingo2089`). Ni el `Config.json` ni el catálogo descifrado se
guardan en el repo (credenciales reales, material por dispositivo);
solo constan la versión, el conteo y la clave que lo abrió.

### Sig-config remota (fallo honesto, sin cambios)

`GET https://cdn.toolsp.site/05da6d93ed43e5ff/259bc7b35aa0` → HTTP 200,
473 bytes, sigue sin descifrar con la clave fija
`xF6qT4S41xonP9eAwQ` (padding PKCS#7 inválido). La app lanzaría
`config_error` y seguiría con los valores por defecto.

### Archivos y textos

- **Decodificadores de archivo:** la app solo define **.sks**
  (`ConfigImportFileActivity`, `pathPattern .*\.sks`) — **excluido por
  regla**, no hay decodificador de archivos.
- **Esquemas de texto:** `xtravpn://<blob>` — verificado en `x()` (no
  es deep link del manifest; solo vía pegar en el diálogo). Sin
  round-trip con perfil real: no hay muestra real de enlace/blob en
  vivo; `--text` se verificó con el blob del asset
  (VERIFIED_SYNTHETIC para la ruta de texto).

### HMAC audit

No HMAC observed for file/catalog integrity, transport MAC, or
connection authentication in the reviewed material. The catalog
envelope authenticates by XXTEA length-word validation plus JSON
structure; no separate MAC is checked.
