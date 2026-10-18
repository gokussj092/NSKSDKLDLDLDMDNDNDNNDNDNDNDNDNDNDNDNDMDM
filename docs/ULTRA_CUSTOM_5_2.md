# Ultra Custom 5.2 — archivos .ua y enlaces ua://

Lector Python independiente: [`ultra_custom_52.py`](../decoders/Python/ultra_custom_52.py).
Analizado desde `Ultra Custom_5.2.apks`: paquete **`hz.custom.vpn`**,
`versionName=5.2`, `versionCode=52`. Las clases Java usan el espacio de
nombres `com.ultra.custom`.

## Uso

Solo requiere Python 3.10 o posterior y PyCryptodome. No necesita el APK,
Android, Java, una biblioteca nativa ni una conexión a Internet.

```bash
python -m pip install pycryptodome
python decoders/Python/ultra_custom_52.py perfil.ua
python decoders/Python/ultra_custom_52.py perfil.ua -o resultado.json
python decoders/Python/ultra_custom_52.py perfil.ua --ask-password -o resultado.json
python decoders/Python/ultra_custom_52.py paquete.ua --password-file clave.txt -o perfiles.json
```

Un enlace `ua://...` puede guardarse en un archivo de texto y pasarse como
entrada. Desde Python también puede procesarse directamente:

```python
from decoders.Python.ultra_custom_52 import decode, run

resultado = decode(contenido_bytes)
resultado = decode("ua://...", password="contraseña original")
texto_json = run(contenido_bytes, password=clave)  # str o None
```

`--ask-password` pide la contraseña sin mostrarla. `--password-file` lee
UTF-8 y retira solamente un LF o CRLF final; conserva espacios y caracteres
Unicode. No se ofrece una contraseña por argumento de terminal.

Las exportaciones UAP1 necesitan su **contraseña original**. Sin ella se
informa `PASSWORD_REQUIRED`; una contraseña incorrecta o una alteración
autenticada produce `AUTH_FAILED`. No se hacen búsquedas de contraseñas ni
se obtiene una clave privada de un servicio remoto.

## Resultado completo

- `type`: `profile` o `bundle`.
- `properties`: todas las propiedades originales como cadenas, incluidos
  campos desconocidos, vacíos, metadatos, notas y flags de importación.
- `comments`: contenido de los elementos XML `<comment>`.
- `embeddedJson.v2rayjson`: vista adicional del JSON V2Ray cuando es válido;
  la cadena original también permanece en `properties.v2rayjson`.
- `profiles`: cada miembro de un paquete, en el orden original. Se conservan
  también las propiedades exteriores `profile.N` para inspección completa.
- `passwordEnvelope`: envoltura original de un miembro protegido del paquete,
  además de sus propiedades ya descifradas.
- `encoding`: identifica XML/EXA1/UAB1 y si hay protección UAP1 exterior.
  Un paquete mixto puede no tener contraseña exterior y sí miembros protegidos.

El lector conserva los CRLF que el exportador escribe literalmente en los
payloads, evitando su conversión automática a LF por el parser XML.
Los flags de HWID, root, operadora, caducidad o bloqueo de edición permanecen
en el resultado; el script no ejecuta las políticas de importación de Android.

Si falla un miembro del paquete, no se entrega el resto como si fuese un
resultado completo. No se escribe ni sobrescribe el archivo de salida hasta
haber descifrado y validado toda la entrada.

## Rutas identificadas en el APK

| Exportación | Contenido antes de la transformación nativa |
| --- | --- |
| Archivo `.ua` individual | XML Java Properties; opcionalmente `UAP1(XML)` |
| Enlace individual `ua://` | `EXA1 || raw-DEFLATE(XML)`; opcionalmente envuelto en UAP1 |
| Paquete de perfiles | `UAB1 || raw-DEFLATE(XML UA-BUNDLE-1)` |
| Miembro protegido de un paquete | XML de tres propiedades con `file.passwordPayload = Base64(UAP1(EXA1 || raw-DEFLATE(XML)))` |

`ConfigParser.encodeBytes` transforma los bytes mediante
`xdevz.o0oooOoO` y usa Base64 URL-safe, sin saltos de línea. La importación
revierte Base64 y llama `xdevz.o0oooo00`, antes de `ProfilePasswordCodec`
y `ProfilePayloadCodec`. El prefijo de enlace se define en
`ConnectionProfileLinkCodec`.

Este formato **no es el motor histórico Ultra/Sandok de `ultra.py`**.
La coincidencia de nombre no implica las mismas claves, Argon2id ni el
mismo contenedor. No se cambia ese motor ni sus extensiones.

### Transformación exterior de libx.so

Los JNI de exportación/importación llaman a la rutina ARM64 en dirección
virtual `0x63ee0`, con flags 0/1. Es una transformación de bytes reversible,
no un cifrado autenticado:

```text
key = A7 88 40 E9 2F 73 4B 36 FB
state = 0x91AC3F12 XOR cada byte de key
por cada byte i:
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5
    conservar state en 32 bits sin signo
    k = key[(i + (state & 255)) % 9]
    plain[i] = ((intercambiar_nibbles(encoded[i]) - state) & 255) XOR k
```

Las constantes están embebidas en el cliente y son material del formato,
no credenciales de una cuenta VPN. Los archivos sin UAP1 no incorporan
autenticación criptográfica; un XML válido no demuestra integridad.

### Protección opcional UAP1

| Offset | Tamaño | Contenido |
| --- | --- | --- |
| 0 | 4 | ASCII `UAP1` |
| 4 | 16 | Salt aleatorio |
| 20 | 12 | Nonce GCM |
| 32 | Variable | Ciphertext |
| Final | 16 | Tag GCM |

Clave: PBKDF2-HMAC-SHA256, **210.000 iteraciones**, 32 bytes y contraseña
UTF-8, compatible con `PBEKeySpec`/JCE para texto Unicode válido.
Cifrado: AES-256-GCM; AAD: los 32 bytes completos de cabecera. Se comprueba
el tag antes de descomprimir o interpretar el contenido. No interviene el
HWID en esta derivación; su valor es una propiedad del perfil.

### EXA1, UAB1 y paquetes

`ProfilePayloadCodec` emplea DEFLATE raw (`nowrap=true`) con un diccionario
UTF-8 exacto de **2.665 bytes y 72 claves**, compartido por EXA1/UAB1. El
script lleva el diccionario incorporado; no necesita descargarlo.

`ProfileBundleCodec` exige `file.bundleFormat=UA-BUNDLE-1`, un
`file.profileCount` entre 1 y 100 y exactamente las entradas `profile.0`
hasta `profile.N-1`, además de las dos propiedades del formato. Cada valor
contiene XML, no otro archivo `.ua` con Base64 exterior.

La envoltura protegida de un miembro tiene exactamente
`file.profilePasswordFormat=1`, `file.profileName` y `file.passwordPayload`.
Su contenido descifrado debe tener `file.proteger=1` y no puede contener
otro paquete ni otra envoltura de contraseña. El exportador actual protege
individualmente los miembros seleccionados y deja el paquete exterior sin
UAP1. El lector también admite UAP1 exterior, permitido por los codecs.

## Validación y alcance

No se adjuntó una exportación `.ua` real. La validación se realizó con
**datos sintéticos** y con el código del APK suministrado:

- Siete variantes producidas por las clases Java `ProfilePasswordCodec`,
  `ProfilePayloadCodec` y `ProfileBundleCodec` extraídas del APK, compiladas
  con JCE. Se ajustó una declaración de excepciones del descompilador y se
  adaptó un helper de concatenación; no se cambió su algoritmo.
- La transformación exterior se ejecutó sobre esos datos con las
  instrucciones ARM64 originales de `libx.so` bajo emulación, sin iniciar
  Android, túneles VPN ni solicitudes de red.
- Siete vectores congelados producidos independientemente en Java/JCE y
  comparados, en ambos sentidos, con la transformación ARM64 real. Todos
  los campos de sus perfiles se compararon con los valores de origen.
- 15 pruebas Python: variantes individuales, enlaces, paquetes abiertos,
  protección exterior, miembros mixtos, Unicode, CRLF, campos futuros,
  100 perfiles, tag/cabecera alterados, límites, errores y CLI independiente.

Productor reproducible: `tests/golden/UltraCustom52VectorGenerator.java`.
El diccionario de referencia se conserva en
`tests/golden/ultra_custom_52_dictionary.txt`; el script descargable no
depende de ese archivo. El productor usa nonces deterministas únicamente
para pruebas y **no es un exportador de producción**.

```bash
python -m unittest tests.test_ultra_custom_52 -v
java tests/golden/UltraCustom52VectorGenerator.java > /tmp/ultra_custom_52_vectors.json
cmp tests/golden/ultra_custom_52_vectors.json /tmp/ultra_custom_52_vectors.json
```

Límites: entrada y XML individual de 16 MiB, XML acumulado de 32 MiB,
100 perfiles por paquete, 100.000 propiedades por XML y contraseña de
16 KiB UTF-8. Se rechazan datos extra después de DEFLATE, XML con claves
duplicadas, DTD personalizados y declaraciones de entidades. El DTD
estándar de Java Properties se reconoce sin abrir una conexión de red.

Errores por `stderr`; resultado JSON por `stdout` o `-o`. Código 0 correcto,
1 formato/contraseña/descifrado, 2 uso o E/S. El script es independiente:
no modifica Android, el registro del bot ni las rutas de otros formatos.
El soporte se limita a lo identificado en esta versión, sin certificar
exportaciones históricas ni versiones posteriores.

| Evidencia | SHA-256 |
| --- | --- |
| APKS suministrado | `59402a1f7548c6fb82b7f650509c14847180b3bd8ad920f45e06281dda299fc7` |
| base.apk | `74c92ec2a4549ba7c6f238a3eb057afcf57e9ac2fa9914a961ef49fcd3934888` |
| split ARM64 | `1601ced237b54e5e95c456157ed80629a4dbd3c74f2030b49431d50064bc7b8e` |
| libx.so | `1f756b5a45ebdbc8bb64d5ca6f2c558269acfbf2f70380b402b38a89c78edf20` |
| Diccionario | `78e8417efba522298311269ddfb9bc1fd29e55cbc758b0c778e3081225b26ca7` |
| Vectores sintéticos | `bb8786bbc4acd1a9cf3d108d1529b2e5584e14df1b0cc61affb15782d4722162` |

No se versionan APK, bibliotecas nativas ni código descompilado de la app.
