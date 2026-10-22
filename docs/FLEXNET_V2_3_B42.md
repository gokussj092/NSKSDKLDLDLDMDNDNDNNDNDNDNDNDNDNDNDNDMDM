# FlexNet V2.3 B42 — FLXCFG v5 y catálogos

Actualización compatible de B46 (2026-10-22): ver [FlexNet V 2.4](FLEXNET_V2_4_B46.md).
El análisis B42 siguiente se conserva como evidencia histórica; sus formatos y
catálogos siguen admitidos. El lector actual amplía el límite de compatibilidad hasta el build 46.

Aplicación analizada: `com.flexnet.tunnel`, **V 2.3**, versionCode **42**.
Motor independiente: `decoders/Python/flexnet_b42.py`.
Rama: `feat/ksh-vpn-python-decoder`, junto con KSH y REESE.

## Resultado y alcance comprobado

- El archivo **`Free Host.flex` es v5 online, modo 2**, suite 1 y mínimo B42.
  Su payload cifrado tiene 713 bytes. Se ha identificado su formato, pero
  **no se recuperó su contenido**: la clave aleatoria se entrega mediante
  autorización del servidor y no está almacenada en el archivo ni en el APK.
- Se descifró y autenticó realmente el catálogo integrado
  **`assets/builtin_servers.dat`**, recuperando sus **7 servidores completos**.
- El modo **v5 offline, modo 1**, se reprodujo desde la biblioteca nativa y
  se verificó con un productor independiente OpenJDK/JCE. No se recibió
  una exportación offline real para certificar ese camino adicionalmente.
- El catálogo remoto tiene una envoltura RSA/GCM distinta. El lector
  acepta una respuesta guardada y la clave privada legítima de esa petición;
  su validación usa vectores sintéticos, sin peticiones al servicio real.

El archivo online no se presenta como descifrado. Sin clave autorizada,
el lector informa `ONLINE_AUTH_REQUIRED` y no produce una salida parcial.

## Uso

El script funciona localmente con PyCryptodome. No necesita Android ni
las bibliotecas `.so` y no realiza peticiones de red.

```bash
python -m pip install pycryptodome==3.23.0
python decoders/Python/flexnet_b42.py perfil_offline.flex -o perfil.json
```

Identificar el formato de la muestra online sin intentar descifrarla:

```bash
python decoders/Python/flexnet_b42.py "Free Host.flex" --inspect
```

`--inspect` informa únicamente cabecera, modalidad, tamaños y requisitos;
no acredita autenticidad del contenido ni recupera configuraciones.

Si el emisor proporciona legítimamente la clave de contenido de un archivo
online, puede leerse desde un archivo local: **32 bytes binarios** o
**64 dígitos hexadecimales**.

```bash
python decoders/Python/flexnet_b42.py perfil_online.flex --file-key-file clave.bin -o perfil.json
```

La clave de contenido no es el valor `wrappedGrant`. El flujo del APK usa
una identidad del dispositivo, retos firmados y una concesión ligada a su
Android Keystore. El script no crea una atestación, no suplanta esa identidad
y no puede reconstruir una clave aleatoria a partir del identificador del
archivo. Para abrir la muestra concreta hace falta esa clave autorizada o
una nueva exportación en modalidad offline.

Extraer y descifrar el catálogo integrado desde el APK descomprimido del ZIP:

```bash
python decoders/Python/flexnet_b42.py "FlexNet V2.3 B42 (1).apk" --builtin-catalog -o flexnet_servers.json
```

También acepta directamente una copia local de `builtin_servers.dat`.
Para una respuesta de catálogo remoto guardada:

```bash
python decoders/Python/flexnet_b42.py respuesta_catalogo.json --rsa-key-file clave_de_la_peticion.pem -o servidores.json
```

La clave RSA debe pertenecer a la petición que recibió esa respuesta. El
lector acepta PEM/DER sin contraseña de 2048–4096 bits. No incluye claves
privadas, tokens, credenciales de servicio ni un cliente de autenticación.

Sin `-o`, imprime solamente JSON en stdout. Los errores van a stderr como
JSON y devuelven **1**; los errores de uso/lectura/escritura devuelven **2**.
El éxito devuelve **0**.

## FLXCFG v5

Ambas modalidades comienzan por seis bytes `FLXCFG`, versión `05`, byte de
modo, suite `01` y mínimo versionCode de cuatro bytes big-endian. El lector
comprueba ese mínimo contra B42 y rechaza suites/generaciones desconocidas.

### Modo 1: exportación offline

| Offset | Tamaño | Campo |
|---|---:|---|
| 0 | 6 | `FLXCFG` |
| 6 | 3 | Versión 5, modo 1, suite 1 |
| 9 | 4 | Mínimo versionCode |
| 13 | 4 | Generación de wrapping: 1 |
| 17 | 16 | Identificador aleatorio |
| 33 | 32 | Salt HKDF |
| 65 | 12 | Nonce de wrapping |
| 77 | 48 | Clave de contenido de 32 bytes + tag GCM de 16 |
| 125 | 12 | Nonce del contenido |
| 137 | 4 | Tamaño del payload cifrado, incluido su tag |
| 141 | Variable | Contenido cifrado + tag GCM |

La clave de wrapping se deriva con **HKDF-SHA256**, salida de 32 bytes,
salt del encabezado e info formada por
`FlexNet/v5/offline/wrap/generation-1` seguida de los primeros 33 bytes.
El material raíz se reproduce desde dos bloques de 32 bytes XOR en los
offsets `0x8d80` y `0x8da0` del `libvpnbridge.so` aportado.

La primera capa **AES-256-GCM** autentica los primeros 77 bytes para
recuperar la clave aleatoria de contenido. La segunda autentica la
cabecera completa de 141 bytes. Solo tras verificar ambas etiquetas se
descomprime gzip y se interpreta el XML Java Properties.

### Modo 2: exportación online

| Offset | Tamaño | Campo |
|---|---:|---|
| 0 | 13 | Magic, versión 5, modo 2, suite y mínimo build |
| 13 | 16 | Identificador del archivo |
| 29 | 12 | Nonce del contenido |
| 41 | 4 | Tamaño del payload cifrado |
| 45 | Variable | Contenido cifrado + tag GCM de 16 bytes |

El contenido usa **AES-256-GCM**, AAD de 45 bytes y gzip. Esta modalidad
no contiene la clave envuelta localmente del modo 1.
`config.m` solicita la operación `file-unlock`; `config.p` firma el reto y
`VpnRouteBridge.transport` usa la concesión recibida. La ruta privada
`flexnet.v5.route` está en Android Keystore. El lector puede procesar el
contenedor con una clave de contenido aportada, pero no sustituye ese flujo.

## Catálogos

**Integrado FBS1:** magic de cuatro bytes, nonce de 12 bytes y JSON cifrado
con AES-256-GCM, incluyendo tag de 16 bytes al final. La AAD es `FBS1` y la
clave es `SHA256("flexnet-builtin-servers-v1\0" || legacyPassword)`.
La contraseña de formato se obtiene de `NativeGuard.getLegacyPassword` en
el núcleo nativo del APK; es material embebido del cliente. El núcleo viene
en `assets/nf.dat`, protegido por la transformación `NFRT` del cargador.

**Remoto:** JSON con `ok`, `mode: flexnet-servers-v1`, `encryptedKey`,
`nonce`, `ciphertext` y `aad`. La clave AES se desenvuelve con **RSA-OAEP,
SHA-256 y MGF1-SHA1**, parámetros explícitos de `P0.g.g`. Después se
autentica GCM con la AAD UTF-8 del documento. La clave RSA es específica
de la petición legítima; no puede derivarse desde una respuesta guardada.

El catálogo y los perfiles conservan todos los campos desconocidos.
Para perfiles, `rawProperties` guarda los valores XML originales,
`xmlComments` conserva comentarios y `embeddedJson` añade una vista de
propiedades que contienen JSON válido, sin reemplazar el valor original.

## Evidencia y validación

Investigación realizada el **18 de octubre de 2026**.

| Artefacto | SHA-256 |
|---|---|
| ZIP aportado | `4f1da1e414189da40461f13f23770c121b1f419d86aa48ca69b4900b5df30615` |
| APK extraído | `8520fec649a1dc04af7b96565fcf27dbdd90b32d1608910c3094c9f205804e38` |
| `Free Host.flex` | `9e57103df2648deb94a959e3b7f5adbb8bde2f55b8019ac20ee6e97a7ee90ac8` |
| `libvpnbridge.so` | `483ed81dd12e929c51aff88f6ce573037fb8deb52a806e3c922b1f6c9235112f` |
| `builtin_servers.dat` | `fbdef95cbb8fbbf5bc8514a7dd814e83cb7210ecab63c58b383b2e7a1fa2eedf` |

El catálogo real produjo **29.172 bytes de JSON**, con **7 registros de
servidores** y etiqueta GCM válida, comparado íntegramente con el script.
No se establecieron conexiones VPN ni se enviaron muestras al servidor.
El APK, los servidores reales y sus resultados no están versionados.

Las fixtures de `tests/golden/flexnet_b42_vectors.json` fueron producidas
independientemente con OpenJDK/JCE. El productor está en
`tests/golden/FlexB42VectorGenerator.java`; Java no es una dependencia del
decodificador ni de la comprobación de las fixtures congeladas.

```bash
python -m unittest tests.test_flexnet_b42 -v
python validate_project.py
python -m unittest discover -s tests -v
```

Límites: 2 MiB de entrada, 4 MiB de XML descomprimido, 128 KiB de catálogo
integrado y límites de estructura JSON. Las etiquetas se verifican antes
de devolver resultados. Se rechazan longitudes inconsistentes y XML con
declaraciones de entidades.

## Integración y compatibilidad

`decoders/Python/flex.py` delega únicamente `FLXCFG\x05` al nuevo lector.
Sus tablas históricas, selección de materiales y lectores **v1–v4** se
conservan. El bot ya tiene `.flex`/`.flexnet` y enlaces `flex://`/`flexnet://`:
el modo v5 offline utiliza esas rutas sin añadir extensiones al catálogo.
El modo online permanece bloqueado en el bot si falta la clave autorizada.
La CLI independiente permite aportar esa clave explícitamente.

No se modifica Android ni se anuncia paridad Kotlin v5. KSH y REESE
permanecen en la misma rama, sin cambios en sus motores.
