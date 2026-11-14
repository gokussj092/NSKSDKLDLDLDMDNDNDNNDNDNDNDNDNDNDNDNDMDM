# Handsome Fast — 2.2 (versionCode 13)

Aplicación analizada: **Handsome Fast**, paquete `com.handsomefast.app`,
versión `2.2`, código 13. Esta carpeta contiene el icono y un lector de
catálogo **independiente**, escrito únicamente con la biblioteca estándar
de **Python 3.10 o posterior**. No necesita el APK al ejecutarse.

| Archivo | Función |
| --- | --- |
| `Handsome_Fast.py` | Catálogo integrado o remoto: Base64 y XXTEA modificado. Descarga HTTPS explícita. |
| `Handsome_Fast.png` | Icono original PNG, 512 × 512 píxeles (origen 500 × 500, reescalado). |
| `Handsome_Fast_archivos.py` | Archivos `.hsome`: hexadecimal → XOR (clave de 12 B de `libputils.so`) → UTF-8 JNI modificado → JSON. `decode()` + CLI (`--text`/`-o`/`--summary`, `--self-test`). Ver `work/NOTES_libputils.md`. |
| `Handsome_Fast_textos.py` | **No se entrega**: no se encontró ningún esquema URI propio ni importación de texto/enlaces (ver abajo). |

## Uso

Desde esta carpeta, descargar el catálogo actual, descifrarlo e imprimirlo:

```bash
python Handsome_Fast.py --url
```

Guardar el catálogo completo o abrir una respuesta guardada previamente:

```bash
python Handsome_Fast.py --url -o catalogo.json
python Handsome_Fast.py respuesta_catalogo.txt -o catalogo.json
python Handsome_Fast.py --url 'https://ejemplo.invalid/catalogo' -o catalogo.json
```

El último ejemplo admite una URL HTTPS explícita; `.invalid` es un dominio
de ejemplo. `--url` sin argumento usa el endpoint original identificado:

```text
https://raw.githubusercontent.com/pipoyrichards/HANDSOMEFAST/refs/heads/main/FEBRUARY
```

El script puede copiarse y ejecutarse por separado. No requiere instalar
dependencias ni aportar una contraseña criptográfica de usuario para este
formato. La API `decode(bytes_o_texto)` es siempre offline; solamente la
opción `--url` realiza una descarga.

## Catálogo: flujo y formato

`OpenVPNClient.z()` solicita el endpoint original con una petición GET de
Volley (`StringRequest`, sin cabeceras personalizadas, sin parámetros y sin
autenticación). El listener `C4638wJ.d()` entrega la respuesta a
`AbstractC0152Fm.c`, compara `Version` con la del catálogo local y, si la
remota es más reciente, guarda el catálogo actualizado. El asset
`assets/gremlin.json` contiene el catálogo integrado en el APK. Ambos usan
el mismo formato:

1. Se eliminan los espacios (`" "`) y saltos de línea (`"\n"`) de la
   respuesta, como hace la app antes de descifrar.
2. Base64 estándar (el lector `K80.n` ignora además cualquier carácter
   fuera del alfabeto).
3. Palabras de 32 bits little-endian y última palabra con la longitud clara.
4. Variante XXTEA con clave UTF-8 compartida `Princie!`, completada con
   ceros hasta 16 bytes.
5. Delta **`-1638454863` / `0x9E5729B1`**, con aritmética Java de 32 bits.
   La constante XXTEA habitual (`0x9E3779B9`) no reproduce este catálogo.
6. `6 + floor(52 / número_de_palabras)` rondas; comprobación de longitud
   entre `4*n - 7` y `4*n - 4`, seguida de JSON UTF-8.

Las funciones `AbstractC0152Fm.a/b/c/f/g` definen el mezclador, el
descifrado y las conversiones. La transformación no añade MAC ni firma
criptográfica; la longitud interna y el JSON solo comprueban la estructura.
La misma clave `Princie!` cifra también los valores de `SharedPreferences`
(`PR.a`/`PR.b`).

Se devuelve **todo el objeto raíz**, incluidas `Free_servers`,
`Premium_servers`, `Vip_servers`, `Private_servers`, `Payloads`, `Username`,
`Password`, `Version` y `Changelogs`, además de campos futuros. No se
mezclan los tweaks locales, no se filtran listas premium y no se limita el
número de servidores a los presentes en el asset. Una descarga fallida
produce un error, sin sustituirla por un catálogo antiguo.

La app, al actualizar, mezcla en `Payloads` los tweaks locales cuyo
`message` empieza por `Custom Tweak` y vuelve a guardar el documento con
`J10.h` (el mismo XXTEA + Base64) en `<filesDir>/gremlin.json`. Este lector
devuelve el documento remoto tal cual, sin esa mezcla.

El nombre del archivo remoto (`FEBRUARY`) está fijado en el código de la
versión 2.2 y parece rotar por mes; si el proveedor lo cambia, la URL del
script debe cambiar igual que la de la app.

## Archivos `.hsome`: flujo y formato (con decodificador)

`ImportTweakActivity` registra la extensión `.hsome` (intent `VIEW`,
esquemas `content`/`file`, `pathPattern: .*\.hsome`). La importación
(`OpenVPNClient.onActivityResult`, código 1001) lee la primera línea del
archivo y llama a `PUtils.pDecrypt(context, línea)`; el resultado es un
objeto JSON de tweak. Si `tweak_password` está vacío se importa
directamente (`B()`); si no, la app pide la contraseña y la compara
después del descifrado (`Z()`). La exportación (`OpenVPNClient.X()`)
serializa el tweak como JSON, lo cifra con `PUtils.pEncrypt()` y escribe
una sola línea en Descargas (`Downloads/HANDSOMEFAST/<nombre>.hsome`).

`B()` valida después del descifrado: `tweak_expiry` (formato
`yyyy-MM-dd-HH-mm`), `hwid_lock` contra el HWID del dispositivo y
`block_rooted` (`"true"`) contra root. Después añade el objeto al arreglo
`Payloads` del catálogo (renombrando `friendly_name` si ya existe) y
guarda el catálogo con `J10.h` (XXTEA `Princie!`). Los campos del tweak
son los de un payload del catálogo (`friendly_name`, `payload`, `sausage`,
`host`, `port`, `dothost`, `message`, `method`, `category`, `query`,
`sslws`) más `tweak_password`, `tweak_expiry`, `hwid_lock` y
`block_rooted`.

El decodificador **sí se entrega** (`Handsome_Fast_archivos.py`):
`pEncrypt`/`pDecrypt` son métodos nativos de `libputils.so`
(`hsome/vpn/app/utils/PUtils.java`), y la librería se recuperó del
split de configuración del APK (`split_config.arm64_v8a.apk`, idéntica
a `libs/libputils.so`). El algoritmo verificado por desensamblado es
hexadecimal → XOR con clave de 12 bytes (`.rodata` 0xc4f68, idéntica a
la constante de la misma familia de HX/TRM) → UTF-8 JNI modificado →
JSON; el detalle completo y las pruebas están en
`work/NOTES_libputils.md`. Lo que sigue sin existir es un archivo
`.hsome` real para contrastar de extremo a extremo: no hay ninguno en
el repositorio ni en el espacio de trabajo. El método del catálogo
(XXTEA `Princie!`) **no** es el de los archivos: `assets/server.psi`,
que también usa `pDecrypt`, no descifra con XXTEA `Princie!`.

`assets/server.psi` es la lista de servidores incrustada del motor
Psiphon (`TunnelVpnManagerPsi.startPsiphon()` la pasa a
`PUtils.pDecrypt()`); no es un catálogo SP-DECODE ni un archivo `.hsome`,
y tampoco descifra con el método del catálogo.

## Textos y enlaces: esquemas URI propios (no encontrados)

El `AndroidManifest.xml` no declara ningún esquema URI propio: solo
`content`/`file` para `.hsome`, y los esquemas `genericidp` y `recaptcha`
de Firebase Auth. No hay lectura de portapapeles ni `ACTION_SEND` para
importar perfiles como texto (el portapapeles solo aparece en
`LogActivity`, para copiar registros). Los únicos enlaces con esquema
propio en las cadenas son `https://t.me/handsomefast` (canal de Telegram)
y el endpoint de registro descrito abajo. Por eso no se entrega
`Handsome_Fast_textos.py`.

## Endpoint de registro (no es el catálogo)

`SplashActivity` registra el dispositivo en el primer uso con un GET de
Volley a:

```text
https://handsomefast.life/api/douser.php?deviceid=<cifrado>
```

El `deviceid` es un identificador aleatorio de 15 caracteres
`[a-z0-9]` cifrado con `PUtils.pEncrypt()` (nativo, mismo bloqueador que
`.hsome`). La respuesta es texto plano: `Success! Created` (se guarda el
identificador) o `Success! Exists` (reintentar más tarde). El 13 de
noviembre de 2026 este endpoint respondió **HTTP 403** a una petición con
un `deviceid` de prueba sin cifrar, por lo que no es utilizable sin la
librería nativa. No interviene en la descarga del catálogo.

## Validación real y pruebas reproducibles

El **13 de noviembre de 2026, ~14:07 PST**, el endpoint original
respondió HTTP 200 y el script descifró la respuesta real:

| Lista | Remoto | Integrado (asset) |
| --- | ---: | ---: |
| `Free_servers` | 21 | 20 |
| `Premium_servers` | 0 | 0 |
| `Vip_servers` | 0 | 0 |
| `Private_servers` | 0 | 0 |
| `Payloads` | 583 | 591 |

Son **21 servidores y 583 payloads** en la respuesta remota observada;
los payloads no se cuentan como servidores. Los totales pueden cambiar.
Se recuperaron todos los campos del documento, sin truncar ninguna lista.
La versión remota es más reciente que la del asset integrado.

- Remoto: 265.744 bytes cifrados; SHA-256 del JSON canónico descifrado:
  `c629cd9365594887a7b9dbd91d6475dc7c0294fea491f29c464fb946ae73f505`.
- Integrado: 269.640 bytes cifrados; SHA-256 del JSON canónico descifrado:
  `62816a3fb08f70c0eccda2dac65249fca1c82b4de46a01a0907748de2a7997eb`.

Se ejecutó la CLI `--url` contra el servicio real y la CLI con el asset
integrado; ambas produjeron el objeto completo con las 9 claves raíz.
El códec se verificó además con round-trip (cifrar con la implementación
espejo de `AbstractC0152Fm.d` y volver a descifrar: documento idéntico).
Entradas inválidas (`""`, Base64 corto, caracteres no Base64) se rechazan
con `FORMAT_ERROR`/`TRUNCATED`. No se probaron conexiones VPN a los
servidores. No se imprimen ni guardan valores descifrados sensibles
(usuarios, contraseñas, hosts o payloads): solo conteos y estructura.

## Procedencia y contrato de salida

- APK base: `a9b8aee8813b54e91c9d3ef4cc1ffed4e6709c077f8fb3d87d4519f1cf95b2d7`.
- Icono: `base.apk/res/drawable/ic_app_icon.png` (500 × 500), reescalado
  a 512 × 512 con Lanczos.
- SHA-256 del PNG: `1e1f8d911dd88b733c1dcb274825618bec76a89579116a2e18ce93fdbe88f4b9`.
- SHA-256 del icono original (500 × 500):
  `6fb601f319ca0f56976578f29cc51391f4369c6a9e78029b46e518b5091a3934`.

El módulo expone `decode(bytes_o_texto) -> dict` y
`run(...) -> str | None`. La CLI imprime JSON completo o lo guarda con
`-o`; los errores se escriben como JSON en stderr. Código 0 al completar,
1 por formato/descifrado/red y 2 por argumentos o archivos. Una entrada
inválida se rechaza antes de escribir la salida; pueden producirse errores
del sistema de archivos durante la escritura.

Límites: 32 MiB de entrada/respuesta, profundidad JSON 64 y un millón de
nodos contando claves. Se rechazan claves duplicadas, números no finitos,
Unicode inválido y listas conocidas con miembros que no sean objetos.
Las peticiones exigen HTTPS, permiten hasta cinco redirecciones HTTPS y
usan timeout de 20 segundos por operación de socket, sin reintentos.

No se versionan APK, respuestas reales ni datos de acceso a servidores.
Este lector es autónomo; no modifica Android ni el registro del bot.

## Pendientes

- Decodificador `.hsome`: entregado (`Handsome_Fast_archivos.py`,
  verificado por desensamblado de la propia `libputils.so` y round-trip).
  Pendiente solo un archivo `.hsome` real para contrastar de extremo a
  extremo.
- El endpoint del catálogo usa un nombre de mes (`FEBRUARY`); vigilar si
  el proveedor rota el archivo y la app deja de actualizarse.
- `douser.php` (registro de dispositivo) también depende de `pEncrypt`
  nativo; no afecta al catálogo.
