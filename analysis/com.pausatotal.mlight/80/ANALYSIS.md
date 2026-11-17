# M Light 3.1.55 — ANALYSIS

Paquete `com.pausatotal.mlight`, versionCode 80, versionName 3.1.55.
Estado global: **PARTIAL** (catálogo VERIFIED en vivo; archivos y
texto VERIFIED_SYNTHETIC — falta una muestra real).

## 1. Método de catálogo (verificado en vivo)

- Descarga: `GET` al `config.json` del repo público del operador en
  GitHub raw, sin cabeceras ni User-Agent propios (defecto de Java),
  timeouts 15 s, exige HTTP 200. La app (clase `Lwo`, AsyncTask) lee
  el cuerpo línea a línea y lo concatena sin saltos. Lo guarda en
  `getFilesDir()` como `ic_launcher.png` (disimulado). Si no existe
  el archivo local, usa el asset `assets/flags/iusacel.png` (config
  ofuscado v1.0.0, no es un PNG).
- Cifrado ("AESCrypt", clase `L...`): texto baybayin (pares de
  caracteres = 1 byte, alfabeto de 17 caracteres) → bytes UTF-8 =
  Base64 (NO_WRAP) → AES/CBC/PKCS7, IV 16 bytes cero, clave = SHA-256
  del hex en mayúsculas de la clave en claro. La clave en claro sale
  de la función nativa `getAESKey()` en `libsec_core.so`, que la
  construye carácter por carácter. Todo el catálogo queda en claro
  tras el descifrado exterior (sin sobres internos: 0 valores con
  caracteres baybayin).
- URL secundaria: `messages-config.json` del mismo repo, mismo
  cifrado (JsonVersion 1.0.26, 1 mensaje de soporte). Verificada en
  vivo; no cableada como segunda fuente (decisión pendiente).
- Resultado vivo (re-corrida 2026-11-17): **v1.0.115, 117
  servidores**, 40 valores distintos de `MyServer`, 3.814 campos
  (1.984 no vacíos). Flags: mz 21, ao 19, nf 13, icon_default 12,
  et 11, br 10. Payload 105, ProxyIP 108, ServerIP 116, SNI 115,
  TokenAuth 22, SlowDNS 12, OpenVPNConfig 2, v2rayJson 1 (enlace
  `vless://` en claro). No hay `.sks`.
- El JSON de resultado lleva SOLO los datos del catálogo, todo
  descifrado; las APIs de descarga NO van en el resultado (regla del
  propietario, 2026-11-15). La re-corrida en vivo es **byte-idéntica**
  a la muestra entregada (`catalogo_vivo.json`).

## 2. Archivos `.pausa` y enlaces `pausa://`

- Filtro del explorador de importar: extensión `pausa` (o sin
  extensión). Exporta con `Properties.store()` → `AESCrypt.encrypt`
  → cadena baybayin-hex. Importa probando (a) Base64 → AES/CBC con
  la contraseña de archivos (clave SHA-256(hex(password)), IV cero),
  (b) formato baybayin-hex/AESCrypt. Después: si empieza por `{` →
  `JSONObject` → `Properties`; si no → `Properties.load()`. La app
  valida `file.blockHwid` = `"1"` o vacío.
- Enlace `pausa://` (también `pausa:`): trim, quita el prefijo,
  corta en `?`, `Uri.decode`, alimenta los bytes como stream de
  importación. El enlace lleva el contenido del archivo (URL-encoded).
- Estado: **NO VERIFICADO de extremo a extremo**. No existe ningún
  archivo `.pausa` real exportado por la app en un teléfono.
  Round-trip sintético verificado 6/6 (ver RESULTS.md).

## 3. ServerUser/ServerPass compartidos — VEREDICTO: LITERAL

En el catálogo vivo v1.0.115, `ServerUser` es idéntico en 112/117
servidores y `ServerPass` en 79/117. El valor compartido es:

```
ServerUser / ServerPass (compartido): 好坌x爾ul友好
```

(8 caracteres, 18 bytes UTF-8.) Los demás servidores usan
credenciales en claro (`celestrox` ×3, `fr`, `fr2`; 33 servidores
mezclan usuario compartido + contraseña en claro `pausado`, y 0
mezclan al revés.)

Veredicto: es la **credencial SSH literal del operador** (nombre de
usuario —y en 79 servidores también contraseña— de una cuenta SSH
real del operador); no hay segunda capa de descifrado. Evidencia
(resumen de NOTES.md §10 del análisis original, scripts `work/inv1.py`
–`work/inv8.py`):

- `Ltt` lee el config y lo descifra UNA sola vez con AESCrypt →
  `JSONObject`; no hay descifrado por campo.
- `MainActivity` (elegir servidor / rellenar UI): `getString` /
  `optString` de `ServerIP`/`ServerUser`/`ServerPass`/… → prefs
  `servidores` (`sshServer`/`sshUser`/`sshPass`/…), verbatim.
- SSH (Trilead `com.trilead.ssh2`): lee prefs `sshUser`/`sshPass` →
  `Connection.authenticateWithPassword(usuario, contraseña)` directo,
  con fallback a clave pública si hay `keyPath`. OpenVPN
  (`libovpncli.so`): `ProvideCreds` con `sshUser`/`sshPass`,
  verbatim. UZ/V2Ray/SlowDNS no usan ServerUser/ServerPass.
- Barrido: en TODOS los métodos que leen prefs `sshUser`/`sshPass`,
  los únicos `StringFog.decrypt` son sobre literales estáticos del
  código; ningún descifrado se aplica jamás al valor de la pref.
- Nativo (`libsec_core.so`): solo `getAESKey` (clave del catálogo),
  `getKeyForVersion`/`getKeyV1026` (devuelven NOMBRES de clave, nunca
  material), `validateSignature` (siempre `1`), `SystemValidator`
  (anti-emulador/Frida). No existe ninguna función de descifrado de
  credenciales.
- Transformaciones directas probadas sobre los 18 bytes UTF-8
  (byte bajo/alto por codepoint, UTF-16LE/BE, latin-1/GBK/Big5/
  Shift-JIS, `codepoint & 0x7F`, XOR 0x20): ninguna da ASCII legible.
  El valor completo NO aparece en ningún DEX, `.so` ni APK; solo
  existe en el catálogo vivo del servidor. Assets bundled (v1.0.0):
  ServerUser/ServerPass vacíos.
- Corroboración por datos: aparece en TODOS los tipos de túnel y NO
  se agrupa por Flag/MyServer; coherente con credencial literal, no
  con cifrado (un cifrado no se mezclaría así con claros).

NO verificado: conexión SSH real contra el servidor del operador
(no se intentó: sería un acceso a un servidor de terceros; el
veredicto descansa en el flujo de código, no en una prueba de red).

## 4. Entrada huérfana `pausa` en `file-formats.json` — VEREDICTO

La entrada existente (`suffix: "pausa"`, nombre `"Generic AES-GCM /
PBKDF2"`, `offlineSupported: true`, `cloudSupported: true`) **NO
describe el formato `.pausa` de M Light**. Evidencia (código vigente
en el head `5df9fc50`):

- `docs/cloud/C0_FORMAT_MATRIX.csv`: `pausa,Generic AES-GCM /
  PBKDF2,decoders/Python/generic_aes.py,python,B,
  experimental_generic_aes_gcm_synthetic,true,false,,spdecode.registry`.
- `decoders/Python/generic_aes.py`: archivos de tres segmentos
  Base64 separados por puntos (salt, nonce, ciphertext con tag GCM
  de 16 bytes), PBKDF2-HMAC-SHA256 con 1000 iteraciones, clave AES de
  16 bytes, AES-GCM. Contraseña de `generic_profiles.py`:
  `AES_PROFILES['.pausa'] = b'Ed\x01'` (la misma contraseña genérica
  que `.hta`, `.ai`, `.tpp`, `.max`, `.hqp`, `.hq`, `.tsd`).
- `.pausa` de M Light: baybayin-hex o Base64 → AES-256-CBC, clave
  SHA-256 del hex de la contraseña de archivos, IV cero, sin salt,
  sin tag, sin PBKDF2. Construcción completamente distinta (modo,
  KDF, codificación y contraseña).

La entrada C0 es un marcador genérico experimental/sintético (fuente
`66.py`) sin motor C8, sin entrada supplied, sin directorio de
proveedor y sin icono. Al registrar M Light en supplied
(`extensions: ["pausa"]`), `load_runtime_file_engines()` la sobrescribe
con el nombre `M Light 3.1.55` y al regenerar con
`scripts/cloud_formats_catalog.py --write` el `file-formats.json`
pasa a llevar el nombre correcto automáticamente. El motor C0
genérico queda como ruta congelada: `pausa` NO está en
`_C8_GENERIC_FALLBACK`, así que un archivo genérico `.pausa` (si
existiera alguno real — no hay evidencia de ninguno; la entrada C0
es sintética/experimental) dejaría de abrirse. Decisión pendiente:
añadir `pausa` a `_C8_GENERIC_FALLBACK` o no (ver REPORT.md).

## 5. Auditoría HMAC

- Integridad de archivos: padding PKCS7 tras AES-CBC (sin tag AEAD);
  no se observó HMAC. Estado: NOT_OBSERVED.
- Integridad de catálogos: misma construcción; no se observó HMAC.
  Estado: NOT_OBSERVED.
- Derivación criptográfica: SHA-256 del hex de la clave; sin HMAC ni
  PBKDF2. Estado: NOT_OBSERVED.
- Transporte VPN: no se revisó el transporte VPN de esta app.
  Estado: NOT_OBSERVED.
- Autenticación al establecer la conexión: no se observó HMAC de
  autenticación de conexión. Estado: NOT_OBSERVED.

La presencia de una biblioteca HMAC no demuestra su uso; aquí no se
observó HMAC en ningún propósito.

## 6. Límites y pendientes

- Falta un archivo `.pausa` real exportado por la app en un
  teléfono (confirmación de extremo a extremo del decodificador).
- Falta un enlace `pausa://` real compartido por la app.
- Segunda fuente `messages-config.json`: decisión pendiente.
- Icono: reescalado 124×124 → 512×512 del icono oficial de Play.
