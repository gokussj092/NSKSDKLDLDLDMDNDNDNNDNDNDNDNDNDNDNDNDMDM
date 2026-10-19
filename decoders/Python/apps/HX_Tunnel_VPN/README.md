# HX Tunnel VPN — Hx-Build14

Aplicación analizada: **HX Tunnel VPN**, paquete `com.hxtunnel.vpn`,
versión `Hx-Build14`, código 14. Esta carpeta contiene el icono original
y dos lectores **independientes**, escritos únicamente con la biblioteca
estándar de **Python 3.10 o posterior**. No necesitan el APK al ejecutarse.

| Archivo | Función |
| --- | --- |
| `HX_Tunnel_VPN.py` | Catálogo integrado o remoto: Base64 y XXTEA modificado. Descarga HTTPS explícita. |
| `HX_Tunnel_VPN_archivos.py` | Archivos `.hxt` o su texto hexadecimal: XOR y texto JNI. Sin acceso a red. |
| `HX_Tunnel_VPN.png` | Icono original PNG, 512 × 512 píxeles. |

## Uso

Desde esta carpeta, descargar el catálogo actual, descifrarlo e imprimirlo:

```bash
python HX_Tunnel_VPN.py --url
```

Guardar el catálogo completo o abrir una respuesta guardada previamente:

```bash
python HX_Tunnel_VPN.py --url -o catalogo.json
python HX_Tunnel_VPN.py respuesta_catalogo.txt -o catalogo.json
python HX_Tunnel_VPN.py --url 'https://ejemplo.invalid/catalogo' -o catalogo.json
```

El último ejemplo admite una URL HTTPS explícita; `.invalid` es un dominio
de ejemplo. `--url` sin argumento usa el endpoint original identificado:

```text
https://ctxrelay.online/updater/e7aa9907021632c39b0e0573e11861
```

Abrir archivos y texto de perfiles:

```bash
python HX_Tunnel_VPN_archivos.py configuracion.hxt
python HX_Tunnel_VPN_archivos.py configuracion.hxt -o perfil.json
python HX_Tunnel_VPN_archivos.py --text 'HEXADECIMAL_DEL_ARCHIVO' -o perfil.json
```

Sustituir el marcador del último ejemplo por el contenido hexadecimal real.
Cada script puede copiarse y ejecutarse por separado. No requiere instalar
dependencias ni aportar una contraseña criptográfica de usuario para estos
formatos. La API `decode(bytes_o_texto)` es siempre offline; solamente la
opción `--url` del lector de catálogo realiza una descarga.

## Catálogo: flujo y formato

`OpenVPNClient.z()` solicita el endpoint original mediante `EW`, una petición
GET. `LJ.e()` entrega su respuesta a `AbstractC0282Km.c`, compara `Version`
y guarda el catálogo actualizado. El asset `assets/gremlin.json` contiene
el catálogo integrado en el APK. Ambos usan el mismo formato:

1. Base64 estándar, con posibles espacios o saltos de línea.
2. Palabras de 32 bits little-endian y última palabra con la longitud clara.
3. Variante XXTEA con clave UTF-8 compartida `Princie!`, completada con
   ceros hasta 16 bytes.
4. Delta **`-1638454863` / `0x9E5729B1`**, con aritmética Java de 32 bits.
   La constante XXTEA habitual no reproduce este catálogo.
5. `6 + floor(52 / número_de_palabras)` rondas; comprobación de longitud
   entre `4*n - 7` y `4*n - 4`, seguida de JSON UTF-8.

Las funciones `AbstractC0282Km.a/b/c/f/g` definen el mezclador, el descifrado
y las conversiones. La transformación no añade MAC ni firma criptográfica;
la longitud interna y el JSON solo comprueban la estructura.

Se devuelve **todo el objeto raíz**, incluidas `Free_servers`,
`Premium_servers`, `Vip_servers`, `Private_servers`, `Payloads`, `Username`,
`Password`, `Version`, `Changelogs` y campos futuros. No se mezclan perfiles
locales, no se filtran listas premium y no se limita el número de servidores
a los presentes en el asset. Una descarga fallida produce un error, sin
sustituirla por un catálogo antiguo.

No se necesita un identificador de cuenta o dispositivo para el GET del
catálogo identificado. No se identificó un esquema propio de enlaces
cifrados para importar perfiles en las rutas revisadas. Las URL utilizadas
para la descarga y las cadenas incluidas dentro de los perfiles se conservan
sin convertirlas en otro formato.

## Archivos `.hxt`: flujo y formato

`OpenVPNClient.X()` serializa el perfil como un objeto JSON y llama a
`PUtils.pEncrypt()` para exportarlo. `ImportTweakActivity` registra la
extensión `.hxt`; las rutas de importación de `OpenVPNClient` leen el texto,
llaman a `PUtils.pDecrypt()` y después analizan su JSON.

La biblioteca ARM64 `libputils.so` permite reconstruir el formato:

```text
Exportación: JSON → JNI modified UTF-8 → XOR repetido → hexadecimal
Importación: hexadecimal → XOR repetido → JNI modified UTF-8 → JSON
```

La clave compartida de 12 bytes es `4%PdXch>fkP]`, equivalente a
`342550645863683e666b505d` en hexadecimal. `xorWithKey` está en `0x1486cc`;
`stringToHex` en `0x1482c4` y `hexToString` en `0x148548` de esta biblioteca.
El exportador escribe dos dígitos hexadecimales por byte. El lector acepta
mayúsculas, BOM UTF-8 y espacios/saltos de línea de transporte; exige una
cantidad par de dígitos completos. No acepta la interpretación permisiva
de números incompletos que permite `std::stoi` en entradas dañadas.

Los caracteres fuera del BMP se guardan como pares de sustitutos UTF-16
codificados por separado, como hace `GetStringUTFChars`. El script trata
esa representación JNI y reúne los pares antes de producir JSON Unicode.
No confunde estos bytes con UTF-8 ordinario de cuatro bytes.

Los controles de firma y paquete de las funciones JNI comprueban el entorno
Android; no derivan la clave del archivo. El formato no contiene salt, IV,
MAC ni una contraseña criptográfica individual.

`tweak_password` está almacenado dentro del JSON: Android compara el texto
introducido **después del descifrado**. También procesa `tweak_expiry`,
`hwid_lock` y `block_rooted` después de leerlo. El lector recupera estos
campos sin ejecutar esas políticas ni renombrar `friendly_name`.
Conserva payloads CRLF, mensajes, cadenas JSON anidadas y campos desconocidos
con sus tipos originales. `assets/server.psi` es un recurso del motor
Psiphon y no se interpreta como una exportación `.hxt`.

## Validación real y pruebas reproducibles

El **18 de octubre de 2026, 23:20 UTC**, el endpoint original respondió
HTTP 200 con el catálogo **25.52**:

| Lista | Remoto 25.52 | Integrado 23.100 |
| --- | ---: | ---: |
| `Free_servers` | 33 | 25 |
| `Premium_servers` | 0 | 0 |
| `Vip_servers` | 0 | 0 |
| `Private_servers` | 0 | 0 |
| `Payloads` | 707 | 635 |

Son **33 servidores y 707 payloads** en la respuesta remota observada;
los payloads no se cuentan como servidores. Los totales pueden cambiar.
Se recuperaron todos los campos del documento, sin truncar ninguna lista.

- Remoto: 368.040 bytes cifrados y 276.023 bytes claros; SHA-256 del JSON:
  `1f8d087754ac76ae8177733d3048661877e1b75e8531b1f7ffc7a2bd804f7882`.
- Integrado: 323.928 bytes cifrados y 242.938 bytes claros; SHA-256 del JSON:
  `55d6caa466448fa2387811ec86af1f86cad9ea67f5dfb4a0e369b9332c57cc06`.

OpenJDK descifró ambas muestras independientemente y coincidió byte por
byte con Python. Se ejecutó la CLI `--url` contra el servicio real y se
comparó el objeto completo. No se probaron conexiones VPN a los servidores.

**No se adjuntó una exportación `.hxt` real.** Su lector se validó con
vectores sintéticos independientes Java, usando `DataOutputStream.writeUTF`
para reproducir el texto JNI. La función XOR ARM64 original se ejecutó
bajo emulación y coincidió con el vector Java en ambos sentidos; solo se
simularon las operaciones de copia y liberación de cadenas C++ externas.
Esta comprobación no ejecuta la aplicación Android completa.

Desde la raíz del repositorio:

```bash
java tests/golden/HXTunnelVectorGenerator.java > /tmp/hx_tunnel_vectors.json
python -m unittest tests.test_hx_tunnel
```

Las 23 pruebas cubren ambos lectores, Unicode JNI, CRLF, metadatos,
las cinco listas, longitudes XXTEA, entradas dañadas, límites, icono,
CLI autónoma y descarga con mocks. Se comprueban listas de 1.000 servidores
y 2.000 payloads sin truncamiento. Solo se versionan fixtures sintéticos
y su productor; las pruebas no consultan el servicio real.

## Procedencia y contrato de salida

- ZIP recibido: `8f77acb9b49bb47670bf1f073babbf92ec8ed6a38dc6c38b9aa39093b092bedb`.
- APKS: `966110f0ba6aa27beb001743096c27a1d5141fcbaa8a725dabacf1fb42b7baaf`.
- APK base: `3c68575c64023b4f321c97440d188818df0e4fb65cbc84c9e4d77179f6415b8c`.
- Icono: `base.apk/res/drawable/ic_app_icon.png`, copiado sin recodificar.
- SHA-256 del PNG: `7af9ffe33fdfbf66598d3713440f09d56effd5b6f9d1d81bec67a470f15773ef`.

Ambos módulos exponen `decode(bytes_o_texto) -> dict` y
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
Estos lectores son autónomos; no modifican Android ni el registro del bot.
