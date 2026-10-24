# REESE TUNNEL 3.23.12 — decodificador Python de archivos .RT

Motor: `decoders/Python/reese_tunnel.py`. Aplicación analizada:
`com.johnreese.fsociety`, versión **3.23.12**, versionCode **129**.
Se añade en la misma rama que KSH VPN: `feat/ksh-vpn-python-decoder`.

## Uso

El script es independiente y funciona sin Android, librerías `.so`, red
ni bot. Su única dependencia externa es PyCryptodome, ya presente en el
proyecto:

```bash
python -m pip install pycryptodome==3.23.0
python decoders/Python/reese_tunnel.py "Telkom unlimited v2ray.RT" -o reese_decoded.json
```

Para una exportación protegida, proporcionar las credenciales originales:

```bash
python decoders/Python/reese_tunnel.py archivo.RT --ask-password -o resultado.json
python decoders/Python/reese_tunnel.py archivo.RT --hwid RC-XXXX-XXXX-XXXX-XXXX --ask-password -o resultado.json
python decoders/Python/reese_tunnel.py archivo.RT --password-file clave.txt -o resultado.json
```

`--ask-password` usa una entrada sin eco; `--password-file` lee UTF-8 local.
Son opciones mutuamente excluyentes. El HWID se normaliza a mayúsculas y
se recortan los espacios exteriores como en la aplicación.

El valor predeterminado de `--signer-sha256` es el SHA-256 del certificado
público del APK aportado. Si una exportación está ligada a otra firma,
hay que indicar el certificado público del APK que la creó:

```bash
python decoders/Python/reese_tunnel.py archivo.RT --signer-sha256 SHA256_HEXADECIMAL_DE_64_CARACTERES -o resultado.json
```

Sin `-o`, imprime solamente el JSON en stdout. En error imprime un objeto
JSON en stderr y devuelve **1**. Errores de uso/lectura/escritura devuelven
**2**; el éxito devuelve **0**. Un fallo de autenticación no produce un
archivo de resultado.

API reutilizable:

```python
from pathlib import Path
from decoders.Python.reese_tunnel import decode, run

audit = {}
document = decode(Path("archivo.RT").read_bytes(), audit=audit)
# document conserva meta, config y todos los campos desconocidos.
# audit contiene el formato y si se verificó autenticación; no credenciales.
formatted = run(Path("archivo.RT").read_bytes())  # JSON str o None en fallo
```

`decode()` acepta `hwid=`, `password=` y `signer_sha256=` como argumentos
por nombre y lanza `DecodeError` con un código estable en caso de fallo.

## Formato actual: RSE5

La ruta `ReeseFile.I` escribe el archivo; `ReeseFile.B` lo importa.
`ReeseFileNative` ofrece una implementación nativa y `ReeseFile.D/i/r`
contiene la alternativa Java que permite reproducirlo sin JNI.

| Offset | Longitud | Contenido |
|---|---:|---|
| 0 | 4 | Magic binario `A7 19 D2 4C` |
| 4 | 1 | Variante `C3` o `C4` |
| 5 | 1 | Flags de protección |
| 6 | 16 | Salt PBKDF2 |
| 22 | 12 | Nonce GCM |
| 34 | Variable | Ciphertext |
| Final | 16 | Tag GCM |

Se usa **PBKDF2-HMAC-SHA256**, **32.768 iteraciones**, clave de 32 bytes y
**AES-256-GCM**. Los primeros 34 bytes completos son AAD y quedan
autenticados. El material de derivación es UTF-8:

```text
REESE-CUSTOM/RSE5|HWID|PASSWORD
REESE-CUSTOM/RSE5|HWID|PASSWORD|SIG:SHA256_CERTIFICADO_PUBLICO
```

En **C4**, `0x01` incorpora HWID, `0x02` incorpora contraseña y `0x04`
incorpora el hash público de la firma. Los componentes desactivados van
vacíos y los separadores permanecen. En **C3**, solo se interpreta el
flag de HWID y siempre existe el componente de contraseña, que puede
estar vacío; esa variante no incorpora la firma.

Tras verificar GCM se elimina el prefijo aleatorio: el primer byte `n`
indica que el tamaño del prefijo completo es `n + 17`. A continuación
hay un entero de cuatro bytes big-endian con la longitud comprimida,
el flujo **DEFLATE sin envoltorio zlib** y un relleno aleatorio final.
El JSON descomprimido conserva los objetos `meta` y `config` completos.

## Lectores históricos identificados

| Variante | Derivación PBKDF2-SHA256 | Capas reproducidas | Evidencia |
|---|---|---|---|
| RSE5 C4 | 32.768, 32 bytes | GCM con cabecera AAD, padding con longitud, DEFLATE | Archivo real + vectores Java |
| RSE5 C3 | 32.768, 32 bytes | GCM con cabecera AAD, padding con longitud, DEFLATE | Código del APK + vectores Java |
| RSE4 | 600.000, 32 bytes | GCM con cabecera AAD de 40 bytes, prefijo aleatorio, DEFLATE | Código del APK + vectores Java |
| RSE3 | 24.000, 192 bytes | HMAC-SHA256, permutación, CBC interior, XOR SHA256, CBC exterior, GCM, prefijo aleatorio, DEFLATE | Código del APK + vectores Java |
| RSE2 | 140.000, 192 bytes | Mismas capas de RSE3 con su derivación histórica | Código del APK + vectores Java |
| RSE1 | 80.000, 128 bytes | HMAC-SHA256, XOR SHA256, CBC, GCM, DEFLATE | Código del APK + vectores Java |

RSE4 deriva desde `REESE-CUSTOM/RSE4|HWID|PASSWORD`. RSE1–RSE3 usan
`REESE-CUSTOM/config-envelope/v1|HWID`, añadiendo `|PASSWORD` cuando la
contraseña recortada no está vacía. Los bloques derivados se destinan,
en orden, a GCM, CBC, flujo XOR, HMAC, CBC interior y permutación.

El lector histórico comprueba primero el HMAC exterior antes de procesar
CBC. RSE1–RSE4 se aceptan como bytes o Base64 con cabeceras de texto; RSE5
también acepta Base64. Se reconoce además el JSON plano de importación,
preservándolo y marcándolo como **no autenticado** en `audit`.

## Validación con el archivo aportado

Investigación realizada el **18 de octubre de 2026**.

| Artefacto | SHA-256 |
|---|---|
| ZIP recibido | `da6c90a8e71e1ccd933389f4c5099577b4f5580ec1e2fa199c261346f67c6ddc` |
| APK extraído | `996e7b14168163f206196209343ebeeadd8e927016c996221643de1c8a132411` |
| `Telkom unlimited v2ray.RT` | `27bfc1071bd124de97e7858676babc091554313499e5fb58076bb4472723d05d` |
| Certificado público del APK | `d834bf8d60bfea09a80a51ccd1a77de3ef966e7833ebb2d0b8dc1f750e38bba7` |

La muestra real es **RSE5 C4, flags `0x04`**: ligada a la firma pública,
sin contraseña de exportación ni HWID criptográfico. Se verificó el tag
GCM y se recuperó un documento JSON de **214.471 bytes** con **13 campos
de metadatos**, **55 campos de configuración** y **un perfil V2Ray**.
La imagen del banner y los campos anidados se conservan sin recortar.
El resultado del script se comparó íntegramente con una extracción
independiente de la misma muestra.

El APK y la muestra real, cifrada o descifrada, no se incluyen en Git.
Las fixtures versionadas son ficticias y usan dominios `.invalid`.

## Investigación del posible catálogo

En el flujo de importación/exportación y las llamadas de red revisadas de
este APK **no se identificó un catálogo remoto de configuraciones VPN**.
Las URLs visibles corresponden a comprobaciones de conectividad,
herramientas de red, navegador, contenido multimedia y contacto.

También existe `NativeVault.sealArchive` con `vault_cover.jpg` para generar
un `icon.jpeg` desde `DevsOnlyScreen`. Esa ruta no acredita un catálogo
VPN: `listSealedEntries` y `readSealedEntry` no tienen llamadas desde el
DEX fuera de su declaración. No se inventa una URL de servidores ni una
opción de descarga para REESE. Una captura o URL concreta de catálogo en
otra versión permitiría investigar ese flujo por separado.

## Pruebas y límites

```bash
python -m unittest tests.test_reese_tunnel tests.test_ksh_vpn -v
python validate_project.py
python -m unittest discover -s tests -v
```

`tests/golden/reese_vectors.json` contiene **16 vectores** cifrados con
OpenJDK 17/JCE. El productor independiente se conserva en
`tests/golden/ReeseVectorGenerator.java`; el motor utiliza PyCryptodome.
Los vectores cubren las seis variantes y protecciones abiertas, con
contraseña, HWID, firma y combinaciones. No se requiere Java para ejecutar
el decodificador ni para comprobar las fixtures congeladas.

Las pruebas comprueban conservación del JSON, manipulación de cabeceras
y etiquetas, HMAC antes de CBC, credenciales incorrectas, normalización,
Unicode, truncamiento, padding, DEFLATE, límites y CLI. La validación real
se limita al C4 aportado; los formatos históricos no están certificados
contra exportaciones reales adicionales.

Límites: 16 MiB de entrada, 32 MiB de JSON descomprimido, profundidad 64,
200.000 nodos JSON y 2 MiB para las capas históricas RSE1–RSE3. Si un
documento contiene un `config.vault` local no vacío, se informa
`DEVICE_VAULT_REQUIRED`: necesita el Android Keystore original y no se
presenta como una recuperación completa. La muestra real tiene ese campo
vacío. Los flags y fechas originales se conservan en el resultado.

Este cambio entrega un script independiente: no registra `.RT` en el bot,
no altera Android, no cambia versiones y no modifica el motor KSH.

## Resultados ligeros (.RT)

El decodificador valida íntegramente el documento autenticado y después **elimina únicamente la clave JSON exacta `bannerImage` en cualquier nivel** (también dentro de listas), con independencia de la imagen Base64. El resto de propiedades permanece intacto. La eliminación afecta a `decode()`, `run()`, la CLI y a las respuestas `rawText`/`structuredJson` del worker Cloud, evitando que el visor o el teléfono tengan que procesar una imagen embebida de tamaño considerable. Los vectores criptográficos congelados conservan el contenido original; las aserciones de salida esperan la omisión intencional del banner. No se almacenan las imágenes eliminadas.
