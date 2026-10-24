# FlexNet B46: muestra real v6 offline

2026-10-24. Se probó `𝑏𝑒𝑘𝑖𝑖𝑛𝑔_𝙗𝙤𝙢𝙗_𝙛𝙧𝙚𝙚.flex` con ambos lectores actuales.
**No se recuperó su contenido:** el resultado es `OFFLINE_KEY_REQUIRED`.
El usuario confirma que la aplicación oficial sí lo importa sin errores.

| Dato observado | Valor |
| --- | --- |
| Tamaño | 1394 bytes |
| SHA-256 | `aed8a10c90ef0ffd64af699796899ae4e32c2332d9f4dfe1dd1f8b3258647e7e` |
| Formato / modo / suite | FLXCFG v6 / 1 / 1 |
| Build mínimo | 46 |
| Cabecera / payload con tag | 45 / 1349 bytes |
| Identificador de época offline | `4794b014b661a5f4deb5523bf3b65ece` |
| Longitud esperada del v5 interior | 1333 bytes; calculada, aún no extraída |

La inspección valida estructura y longitudes; no verifica la etiqueta GCM sin
clave. Es una modalidad distinta de los dos archivos v5 online anteriores:
no utiliza su concesión de importación ni deriva su clave de una contraseña
escrita por el usuario.

## Ruta confirmada en el APK

En `com.betlog.ultrasshservice.config.d`, el setup `l` solicita épocas offline
al servidor mediante `offline-key-start`/`offline-key-finish`. Según el modo,
importa la clave de forma segura o desenvuelve temporalmente 32 bytes RSA y
los importa en Keystore. Después borra ese buffer. La preferencia `active`
es solo un identificador: no contiene la clave AES.

`s(KeyStore,String)` recupera `flexnet.offline.epoch.<id>` y exige protección
hardware y `getEncoded()==null`. Es una clave de época provisionada en cada
dispositivo; el identificador del archivo no permite calcular sus bytes.

`w(BaseActivity,byte[])` busca la época correspondiente y abre AES-GCM usando
nonce `[29:41]`, AAD `[0:45]` y payload desde 45. Se verificó el descriptor real
`(Lcom/betlog/baho/activities/BaseActivity;[B)[B` en DEX: **50 instrucciones**,
incluido `Cipher.doFinal([B,int,int)`. Devuelve un contenedor v5 offline, que el
lector existente puede abrir con su wrapping interno. Esta operación de
apertura no necesita una petición online por cada archivo si el setup ya está
disponible en el dispositivo.

## Auxiliar de recuperación preparado

El [observador B46](../scripts/apk_analysis/flexnet_b46_capture.js) ahora también
intercepta `d.w` conservando argumentos, resultado y excepciones originales.
Tras una apertura exitosa copia el v5 interior y lo vincula por SHA-256 al v6
de entrada. No solicita ni exporta la clave hardware. Se carga con el mismo
REPL de Frida del [procedimiento de importación](FLEXNET_V2_4_AUTHORIZED_IMPORT.md).
Requiere Android instrumentable: **todavía no se probó en un teléfono**.

Después de importar el archivo normalmente con el observador activo, el log
local contiene `FLEXNET_OFFLINE_CAPTURE`, distinto del grant online. Sustituir
`perfil_v6.flex` por la ruta de esta muestra:

```bash
umask 077
python scripts/apk_analysis/flexnet_collect_grant.py perfil_v6.flex /ruta/privada/flex-import.log /ruta/privada/interior.flex --offline-inner
python decoders/Python/flexnet_b42.py /ruta/privada/interior.flex -o /ruta/privada/resultado.json
```

El colector exige esquema exacto `flexnet-v6-opened-inner/1`, hash coincidente,
Base64 canónico y longitud interior `len(v6)-61`. Abre ambas capas GCM del v5,
gzip, XML y campos protegidos antes de guardar el `.flex` interior con permiso
0600, sin sobrescritura. El log/interior contienen información sensible y no
se guardan en Git.

El host **no puede verificar independientemente el tag exterior v6** sin la
clave: esa verificación depende de la llamada original observada en la app.
El vínculo al v6 depende de una captura local de confianza. No se admite un
interior arbitrario como prueba de descifrado de la muestra recibida.

Validación local: **32 pruebas Python y cinco pruebas Node con mocks**. El v6
y v5 sintéticos provienen del productor JDK independiente; se compara todo el
documento y se prueban tags alterados, otro archivo, esquema duplicado, límites,
permisos, CLI y propagación de fallos. Esto comprueba el auxiliar, **no acredita
el descifrado de este archivo real ni una captura Frida en Android**.
