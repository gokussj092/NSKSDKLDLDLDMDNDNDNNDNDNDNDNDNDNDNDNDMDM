# HTTP FenixVPN 19.4

![HTTP FenixVPN](HTTP_FenixVPN.png)

Lectores Python independientes para `com.fenix.vpn`, versión **19.4**, código
**181**. Analizados directamente a partir del APK proporcionado; los scripts
funcionan sin instalar Android ni conservar el APK.

| Entrada | Script | Resultado |
| --- | --- | --- |
| Catálogo de servidores descargado por la app | `server_catalog_decoder.py` | JSON completo; **300 servidores** observados |
| Catálogo separado de perfiles de usuario | El mismo script con `--users` | JSON completo; **1 perfil** observado |
| Archivo importado `.sks` actual | `file_decoder.py` | Todas las entradas XML y XML original |
| Archivo `.sks` antiguo compatible con el importador | El mismo lector de archivos | DES binario → Java Properties XML |

El catálogo integrado en `assets/flags/config.png` tiene **1 servidor** y
`assets/flags/usr.png` tiene **1 perfil**. No son sustitutos de las descargas.
La comprobación remota del 2026-10-19 obtuvo 300 servidores y un perfil de
usuario. Las cantidades pueden cambiar cuando el proveedor actualice sus datos.

## Ejecución

Python 3.10 o posterior y PyCryptodome:

```bash
python -m pip install -r requirements.txt
python server_catalog_decoder.py > servidores.json
python server_catalog_decoder.py --users > usuarios.json
python server_catalog_decoder.py copia_cifrada.txt > catalogo.json
python server_catalog_decoder.py --stdin < copia_cifrada.txt > catalogo.json
python file_decoder.py configuracion.sks > configuracion.json
python file_decoder.py < configuracion.sks > configuracion.json
```

Sin archivo ni `--stdin`, el lector de catálogo consulta exclusivamente la URL
fija correspondiente recuperada de `C3466.C3467` o `C3466.C3468`. No admite una
URL arbitraria ni sigue redirecciones. Las copias locales y `run(data: bytes)`
son siempre operaciones sin red. La salida JSON va a stdout; los errores
breves van a stderr con un código de salida distinto de cero.

## Métodos confirmados en esta versión

### Catálogos

`C3466.OooO0OO` descarga por GET; las respuestas de servidores y usuarios pasan
por `AbstractC6343.OooO00o` y se guardan en los archivos privados de la app.

1. Base64 estándar → `WakkoDev` de 8 bytes, sal de 8 bytes y bloques cifrados.
2. Derivación MD5 encadenada: `D[i] = MD5(D[i-1] + passwordUTF8 + salt)`;
   los primeros 32 bytes forman la clave y los siguientes 16 el IV.
3. AES-256-CBC con PKCS#7 → JSON UTF-8 completo.
4. Los **27 campos conocidos** de cada servidor y **6 campos conocidos** de
   cada usuario se descifran según `AbstractC6344.OooO00o`: Base64 URL-safe,
   IV prefijado de 16 bytes, clave UTF-8 truncada/rellenada a 32 bytes,
   AES-CBC y rotación inversa de cinco posiciones (`C6334.OooO0OO`, shift 21).

`field_names.json` enumera las claves exactas resueltas desde los recursos del
APK. Se conservan las claves opacas originales. Los campos desconocidos,
`serverType`, `tunnelType`, opciones BHTTP y `SshAuthMode` conservan sus valores
y tipos. `Usuarios[].Name` es texto plano y se conserva. Los campos opcionales
vacíos siguen vacíos; no se sustituyen por el indicador de error de la interfaz
original. La rotación reproduce las operaciones sobre caracteres UTF-16 de
Java, incluidos los casos que no corresponden a una simple rotación ASCII.

No se combinan servidores y usuarios ni se asignan credenciales por deducción.
La consulta Cloud de la ficha pública recupera servidores; `--users` permite
obtener por separado el otro catálogo original.

### Archivos

`ConfigImportFileActivity` reconoce `.sks` y llama a `AbstractC3197.OooO0O0`.
La implementación observada admite:

- **Actual:** tres segmentos `Base64(salt32).Base64(nonce12).Base64(cipher+tag16)`.
  PBKDF2-HMAC-SHA256, 1000 iteraciones, clave AES de 128 bits y AES-GCM sin AAD.
  Parámetros y contraseña proceden de `C3365.C3366`, `C3337` y `C3335`.
- **Antiguo:** DES-ECB/PKCS#5 sobre bytes binarios, con los primeros ocho bytes
  de la contraseña literal del importador (`AbstractC3319`).

El contenido descifrado es Java Properties XML. La salida incluye `entries`
ordenadas y `raw_xml` íntegro: conserva duplicados, claves desconocidas,
contraseñas, valores multilínea, cadenas vacías y flags como texto. La etiqueta
GCM se verifica antes de devolver contenido. Un fallo GCM no intenta DES.

El APK conserva `ConfigExportFileActivity` y la rutina de cifrado de `C3337`,
pero el `onClick` observado no llama a un exportador. **No se certifica una
exportación utilizable desde la interfaz de esta versión** ni una exportación
real independiente, porque no se proporcionaron muestras `.sks` externas.
Las pruebas de archivos usan vectores sintéticos de las recetas recuperadas.
No se ha confirmado un esquema de enlaces propio para importar perfiles.

## Integración y compatibilidad

Todo permanece en la rama `feat/austroplus-vpn-13-0-1-decoders`, PR #96.
El worker C8 selecciona este lector para `.sks` GCM/binario y conserva
`decoders/JavaScript/sks.js` para el sobre JSON histórico de SocksIP con `d/v`.
La elección ocurre antes del descifrado; no hay reintento tras un fallo GCM.
El archivo histórico y sus snapshots no se modifican. C0 sigue con **240**
rutas y C8 con **246** extensiones efectivas.

El proveedor fijo `http-fenixvpn` se registra en bridge, broker HTTPS,
OpenAPI y catálogo público. El icono publicado es idéntico al original. La
versión mínima del catálogo sube a **9** y QA mantiene incrementos monótonos.
Los interruptores de despliegue conservan sus valores predeterminados.

La protección nativa y los componentes de anuncios observados no son
dependencias de estos lectores. El archivo adicional `assets/config/config.json`
y el catálogo de anuncios no se usan como alternativa al catálogo de servidores.
No se hicieron cambios en la aplicación Android, despliegues ni releases.

## Límites y evidencia

Entradas: 5 MiB para archivos y 8 MiB para catálogos. Salida: 8 MiB. Profundidad
máxima: 64. Se rechazan JSON duplicado/no finito, campos cifrados malformados,
HTML remoto, sobres incompatibles y declaraciones de entidades XML. CBC/DES
no aportan autenticidad: padding y estructura válidos no sustituyen un MAC.

El catálogo completo local/remoto se comparó con Java: **2127 campos no vacíos**
del catálogo real de servidores, además de los perfiles de usuario, sin recortar
listas ni modificar tipos. Consulte [TESTING.md](TESTING.md) y
[manifest.json](manifest.json) para trazabilidad y alcance exacto. No se incluyen
el APK, las descargas reales ni credenciales del proveedor en Git o en el ZIP.
