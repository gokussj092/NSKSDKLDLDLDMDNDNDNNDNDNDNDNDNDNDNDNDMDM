# FlexNet V 2.4 B46: recuperación mediante una importación autorizada

2026-10-24. Este avance **no descifró las dos muestras reales**. Añade una ruta
concreta para aprovechar la importación que el usuario confirmó que funciona
en su teléfono. Hace falta capturar la concesión ya desenvuelta dentro de esa
importación. No hay un dispositivo Android conectado en el entorno de análisis.

El APK coincide exactamente con el [análisis B46](FLEXNET_V2_4_B46.md).
Las dos muestras son FLXCFG v5, modo 2, suite 1, mínimo build 46:

| Muestra | Bytes | Payload cifrado | SHA-256 |
| --- | ---: | ---: | --- |
| `free (1).flex` | 1388 | 1343 | `853621417da94b6d5effa5db47ad481d193ec37c7a960d1a5f25dbc6ffbb1b76` |
| `MX በነጻ 00ብር 🚀.flex` | 1826 | 1781 | `09845c71d68ccda1e5a620ed204ebadb0009f3c6e33f6ec117e6ac3e68504a81` |

La cabecera tiene 45 bytes; no contiene clave de contenido ni una clave envuelta
localmente. Esta modalidad no deriva su clave de una contraseña del usuario.
El material legacy del catálogo y el wrapping offline no abre estos archivos.

## Flujo comprobado en DEX y biblioteca nativa

Los nombres completos pertenecen a `com.betlog.ultrasshservice.config`.
`y.b` envía `fileId` y SHA-256 completo a `A.g(...,"file-unlock",...)`.
`A.h` obtiene un reto y firma la operación con `flexnet.v5.request` del Keystore.
El resultado contiene `wrappedGrant`; no es una clave AES utilizable directamente.

`VpnRouteBridge.transport([B,[B,[B,[B,String,int,boolean)` llama al método nativo
`s`, dirección ARM64 `0x3360ac`. Recupera `flexnet.v5.route` del Android Keystore
y usa RSA-OAEP con SHA-256, MGF1-SHA1 y etiqueta vacía. La concesión desenvuelta
debe medir exactamente **117 bytes**, sin magic ni prefijo:

| Offset | Bytes | Campo |
| --- | ---: | --- |
| 0 | 32 | Clave AES-256 del contenido |
| 32 | 16 | Identificador del archivo, cabecera `[13:29]` |
| 48 | 32 | SHA-256 de todo el archivo cifrado |
| 80 | 32 | Nonce del reto de esta operación |
| 112 | 4 | Mínimo build, big-endian, igual a cabecera `[9:13]` |
| 116 | 1 | Operación: 2 para importar; 1 corresponde a exportar |

El bloque `0x336a10..0x336a88` compara los cuatro bindings y la operación.
`0x335d8c` solo valida la cabecera y copia identificador/nonce/build: **no deriva
la clave AES**. Tras validar la concesión, se abre AES-GCM con nonce `[29:41]`,
AAD `[0:45]` y tag final de 16 bytes; siguen gzip, XML Properties y campos FLXFLD.

El enrolamiento requiere dos claves del Android Keystore y cadenas de
atestación. Se identificaron `/api/v5/enrollment/start`, `/enrollment/finish`,
`/challenge` y `/execute`, bajo el prefijo `/api/v5`. No se creó una identidad
de pruebas ni se sustituyó la atestación. Un único intento de enrollment/start
con JSON vacío y el CA embebido falló antes de HTTP por verificación de cadena
TLS. No demuestra caída del servidor. No se desactivó la verificación TLS.

Se consultaron las guías [Android](https://github.com/morluto/rea/blob/main/docs/android-analysis.md)
y [nativas](https://github.com/morluto/rea/blob/main/docs/native-investigation.md)
de REA: descriptor real, tabla JNI y ejecución aislada frente al binario exacto.
No fue necesario instalar REA/Ghidra para estas comprobaciones.

## Captura en el dispositivo que ya importa el archivo

Requiere un Android **instrumentable con Frida** y acceso al proceso oficial
FlexNet B46; normalmente un dispositivo de análisis con root/frida-server
configurado y versiones compatibles. No se ha probado esta captura en un
teléfono en esta sesión, ni se garantiza que funcione en un dispositivo sin
instrumentación. Una exportación offline v6 tampoco es portable por sí sola:
conserva su capa de clave del setup en Keystore.

El observador [flexnet_b46_capture.js](../scripts/apk_analysis/flexnet_b46_capture.js)
se carga mediante el REPL de Frida, que proporciona el puente Java incluso en
Frida 17. Ver [API oficial](https://frida.re/docs/javascript-api/) y opciones
oficiales de [conexión](https://github.com/frida/frida-tools/blob/main/frida_tools/application.py)
y [log](https://github.com/frida/frida-tools/blob/main/frida_tools/repl.py).
Abrir la aplicación oficial y, desde el equipo conectado por USB:

```bash
umask 077
frida -U -N com.flexnet.tunnel -l scripts/apk_analysis/flexnet_b46_capture.js -o /ruta/privada/flex-import.log
```

Esperar `FLEXNET_CAPTURE_STATUS ready`, importar **normalmente** cada archivo
con internet y cerrar el REPL al terminar. El observador llama a los métodos
originales con los mismos argumentos. Solo registra el resultado RSA de 117
bytes de la operación de importación activa, y emite la captura cuando el
transporte nativo devuelve contenido sin excepción. No cambia claves, flags,
peticiones, atestación ni TLS. No extrae la clave privada del Keystore.

El log y las capturas contienen la clave AES: conservarlos localmente, fuera
de Git. El colector selecciona por hash y **descifra y autentica el documento
completo antes de guardar** la captura con permiso 0600, sin sobrescribir:

```bash
python scripts/apk_analysis/flexnet_collect_grant.py "free (1).flex" /ruta/privada/flex-import.log /ruta/privada/free-grant.json
python scripts/apk_analysis/flexnet_collect_grant.py "MX በነጻ 00ብር 🚀.flex" /ruta/privada/flex-import.log /ruta/privada/mx-grant.json
python decoders/Python/flexnet_b42.py "free (1).flex" --grant-capture /ruta/privada/free-grant.json -o /ruta/privada/free.json
python decoders/Python/flexnet_b42.py "MX በነጻ 00ብር 🚀.flex" --grant-capture /ruta/privada/mx-grant.json -o /ruta/privada/mx.json
```

`flex.py` acepta la misma opción y devuelve su vista normalizada, conservando
`rawProperties`, `protectedFields` y `decodedProperties`. En Python se usa
`decode(data, grant_capture=capture_bytes)` o `flex.run(data, grant_capture=...)`.
No se mezcla con `file_key`/`offline_key`; no se añade un campo público al gateway.

La captura JSON usa `schema: flexnet-v5-authorized-grant/1`, `fileSha256`,
`challengeBase64` (32 bytes) y `grantBase64` (117 bytes). Valida claves JSON
únicas, esquema exacto, Base64 canónico, tamaños, bindings y GCM. Los bindings
no prueban por sí solos procedencia del servidor; la autorización ocurre en la
app y GCM comprueba que la clave abre el archivo. `wrappedGrant` sigue siendo
ciphertext RSA ligado al dispositivo y no sustituye esta captura.

## Validación y puntos pendientes

**28 pruebas Python y tres pruebas Node de flujo con mocks aprobadas**. El
productor JDK independiente genera el perfil, concesión y reto sintéticos; el
XML íntegro coincide. Se conservan v1–v6, catálogos B42 y campos protegidos.
El bloque ARM64 original acepta el vector válido, rechaza cada uno de los 85
bytes de binding alterados y acepta una clave alterada en esa fase; la posterior
verificación GCM la rechaza. Son **87 casos nativos**, sin simular JNI ni RSA.

Las pruebas del observador comprueban argumentos/retornos originales,
propagación de excepciones, exclusión de exportaciones y copia de la concesión
antes de que el código nativo borre el array. **No son una prueba en Android.**

Archivo, catálogo FBS1 y catálogo remoto RSA son rutas distintas. El APK B46
incluye el mismo asset FBS1 de 29204 bytes del análisis B42 (SHA-256
`fbdef95cbb8fbbf5bc8514a7dd814e83cb7210ecab63c58b383b2e7a1fa2eedf`);
se volvió a autenticar GCM y se recuperaron sus **siete servidores** completos.
El código B46
también identifica `cloud-fetch` para descargar un perfil por código y verificar
su hash; no evita la posterior autorización de `file-unlock`. Las rutas de texto
históricas `flex://`/`flexnet://` permanecen, sin demostrar que representen las
claves de estas muestras. El catálogo no permite deducir sus claves.

Pendiente concreto: ejecutar el observador en un dispositivo que importe las
muestras y obtener una captura válida por archivo. Hasta verificar ambas
etiquetas GCM y sus documentos, **no anunciar descifrado real ni automático**.
