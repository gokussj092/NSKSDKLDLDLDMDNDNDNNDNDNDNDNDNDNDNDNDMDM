# NPV Tunnel: descifrado Python de NPVS v5

`decoders/Python/npvs.py` descifra el archivo real suministrado de NPV Tunnel
124.0.37 (`com.napsternetlabs.napsternetv`, versionCode 577). Es independiente de
Android y de la APK durante su ejecución. Solo requiere Python 3 y PyCryptodome.

```sh
python -m pip install pycryptodome
python decoders/Python/npvs.py archivo.npvs -o resultado.json
```

El resultado conserva `metadata` (incluida la política del archivo) y `document`,
cuyo arreglo `configs` contiene las configuraciones completas con sus tipos JSON.
Sin `-o`, se escribe el JSON en stdout. Un archivo inválido produce un mensaje en
stderr y código de salida 1. La función `run(file_bytes)` devuelve el mismo JSON
como texto; `decode_npvs(file_bytes)` devuelve un diccionario y lanza `DecodeError`
si falla una validación. La decodificación offline conserva la política, pero no
ejecuta las restricciones Android de red, vencimiento o atestación.

## Alcance comprobado

Actualización 2026-10-22: **v5 passphrase también disponible**, contraseña UTF-8
mediante PBKDF2-HMAC-SHA256, 600000–10000000 iteraciones. Se verificó una muestra
real completa (16 registros, nueve campos internos `npvs1:`) y los métodos
app-key anteriores mantienen sus pruebas. La versión 6 recipient se reconoce
y se valida su firma/framing, pero **no se descifra con una public key sola**.
Detalles y límites en [NPVS_PROTECTED_FILES.md](NPVS_PROTECTED_FILES.md).

```sh
python decoders/Python/npvs.py archivo.npvs --credentials-stdin < credenciales.json
```

`credenciales.json` contiene `{"password":"contraseña de exportación"}` para
passphrase, o `{"publicKey":"clave pública Base64URL"}` para identificar un
destinatario. No se pasa la contraseña por argv/env. `publicKey` solo permite
comprobar coincidencia; la ausencia de clave privada devuelve
`PRIVATE_KEY_REQUIRED`, sin JSON parcial. API: `run`, `decode_npvs` y
`decode_npvs_complete` aceptan los kwargs opcionales `password` y `public_key`.

### Alcance original del 10 de octubre

Soporta el contenedor binario `NPVS`, versión 5, cabecera compacta versión 1,
modo app-key 2, identificador de clave 2. El archivo probado no tiene destinatarios.
La cabecera admite registros de destinatario, pero otros modos, versiones y
archivos no han sido validados. El decodificador anterior `NPVTUNNEL.py` y los
registros de extensiones existentes se conservan para su integración posterior.

La APK adjunta estaba firmada nuevamente con un certificado de pruebas Android.
Para recuperar las tablas originales se usó la huella SHA-256 del firmante original
`e03dcc51aad45456b97b6331c08a2f6a67eb9516e931a3e6cefcd0eeee5801d4`, publicada en
la [ficha de distribución de 124.0.37](https://www.apkmirror.com/apk/vonmatrix-co-ltd/napsternetv-v2ray-psiphon-ssh/npv-tunnel-v2ray-ssh-124-0-37-release/npv-tunnel-v2ray-ssh-124-0-37-android-apk-download/).
La huella se comprobó contra el HMAC interno del código nativo; también se verificó
la autenticación del recurso `assets/rt.dat`. Las tablas recuperadas están
incluidas como datos comprimidos en el script, con comprobación SHA-256. No son
una clave extraída del archivo de configuración ni requieren la APK al ejecutar.

## Método reproducido

1. Lee `NPVS | v5 | BE32(header_len) | header | nonce12 | BE32(body_len) | body | signature64`.
   Comprueba los límites y la firma ECDSA P-256/SHA-256 (R y S de 32 bytes cada uno)
   sobre todos los bytes anteriores a la firma, con la clave pública de la cabecera.
   Esa firma comprueba consistencia con la clave incluida; no identifica a un
   editor de confianza externo.
2. Evalúa las tablas white-box de `libnpvtunnel.so` sobre la sal de 16 bytes.
   Deriva `KDK = SHA256("npvtunnel/appkey/v2 " || whitebox(salt) || configId)`;
   el espacio final del prefijo es obligatorio. Abre la DEK de 32 bytes con
   ChaCha20-Poly1305 y AAD igual a la sal.
3. Deriva la clave de metadatos mediante HKDF-SHA256(DEK, salt=nonce,
   info=`NPVS-v5/metadata`). Autentica y abre los metadatos usando el nonce del
   contenedor y la cabecera compacta anterior a la longitud de metadatos como AAD.
4. Reconstruye la cabecera JSON original (configId, fecha, creador, política y
   destinatarios `null`), con Base64URL sin padding y canonicalización JSON del
   código Go. Calcula el contexto SHA-256 de
   `NPVS-v5/source-fields-v1/ || canonical_header || nonce` y comprueba su unión
   con el contenedor `NPF\x01`.
5. Valida el HMAC-SHA256 del inventario. Sus claves se obtienen por HKDF-SHA256
   con DEK, sal=contexto e info=`NPV-fields-v1/inventory/ || BE16(0)`.
   Cada registro usa info=`NPV-fields-v1/field/ || BE16(id)` y ChaCha20-Poly1305
   con nonce cero de 12 bytes (una clave distinta por id). El AAD es
   `NPV-fields-v1/record/ || contexto || BE16(id) || BE32(plain_len)`.
6. Descifra los escalares JSON y el registro 65535 de estructura. Sustituye las
   referencias de la estructura por sus valores y exige que se usen todos los
   registros. No se adivinan campos ni se devuelve descifrado parcial.

## Pruebas reales

- APK SHA-256: `246323d3b9979036bd0f5b60b8de7bf25c7adfdef0d3e6952787c3de2daa6379`.
- Archivo de entrada: 5443 bytes, SHA-256
  `2e321bb8c506dbac8a1b2848ff8a05fb4f811df34536853b2a965d6dfd197867`.
- Resultado: una configuración; 106 valores escalares y un registro de estructura.
- Firma ECDSA, DEK, metadatos, contexto, HMAC y las 107 etiquetas de registro válidos.
- SHA-256 del documento JSON UTF-8, claves ordenadas y separadores compactos:
  `eaa7e033fa9c5677d605628a4bbc32961c1b61c44e0e329393fe8776eaa47bfb`.
- Evaluador white-box comparado con la rutina ARM64 en ocho bloques independientes.

Las pruebas publicadas incluyen tres vectores nativos. La muestra real se mantiene
privada; se activa localmente así:

```sh
SPDECODE_NPVS_REAL_FILE=/ruta/archivo-real.npvs \
  python -m unittest discover -s tests -p 'test_npvs_v5.py' -v
```

Las pruebas reales comprueban el documento completo, la CLI, todos los prefijos
truncados y rechazos por cambios en firma, DEK, metadatos, contexto e inventario.
También alteran individualmente las 107 etiquetas de registro y recalculan el HMAC
del inventario para comprobar cada AEAD de manera independiente. No se publican
la APK, el archivo real, las credenciales descifradas ni claves derivadas de él.
