# VPN PLUS PERÚ 1.0 — lector Python y resultado de la revisión

## Hallazgo principal: este APK usa archivos `.gol`

El archivo recibido, `VPN_PLUS_PERU_optimizada_sign.zip`, contiene un APK
con nombre **VPN PLUS PERÚ**, paquete **`com.akunt.vpn`**, `versionName=1.0`
y `versionCode=1`.

**No se identificó un catálogo remoto, su URL ni un flujo de actualización
de servidores en esta versión.** Por tanto, no se presenta una descarga
automática ni un número de servidores recuperados como si se hubiesen
verificado. La hipótesis de que esta versión solo usa catálogos no coincide
con el código del APK enviado.

La aplicación sí contiene:

- `MainActivity.importarConfig`: selecciona un archivo `.gol` mediante
  Android y lee su contenido como texto UTF-8.
- `MainActivity.validarYRestaurar`: importa AKN3, AKN2, el cifrado legado
  sin prefijo o un objeto JSON sin cifrar.
- `ExportConfigActivity`: exporta AKN3 a `Download/VPNPlusPeru/*.gol`.
  La propiedad interna `__app_version="3.0"` describe la exportación;
  no cambia el `versionName=1.0` del manifiesto.
- `CryptoUtils`, `CryptoUtilsV2` y `CryptoUtilsV3`: los tres motores.

Se revisaron los dos DEX, los recursos y los puntos de acceso a red del
paquete de la aplicación. Las URL literales son de WhatsApp y de consulta
de IP (`api.ipify.org`); no son catálogos. Las conexiones HTTP de
`HostValidatorActivity` comprueban un host introducido por el usuario.
`assets/geoip.dat` y `assets/geosite.dat` son datos de enrutamiento de Xray,
no listas de credenciales VPN; el otro asset es `dnstt-client`.

## Script y uso

Motor independiente: [`vpn_plus_peru.py`](../decoders/Python/vpn_plus_peru.py).
Solo necesita Python 3.10 o posterior y PyCryptodome; no requiere el APK,
Android, Java ni los otros módulos de SP-DECODE al ejecutarse.

```bash
python -m pip install pycryptodome
python decoders/Python/vpn_plus_peru.py configuracion.gol
python decoders/Python/vpn_plus_peru.py configuracion.gol -o resultado.json
```

También puede descargar una ubicación HTTPS indicada por el usuario,
descifrar su respuesta e imprimir el JSON completo:

```bash
python decoders/Python/vpn_plus_peru.py --url "https://example.invalid/configuracion.gol"
python decoders/Python/vpn_plus_peru.py --url "https://example.invalid/configuracion.gol" -o resultado.json
```

**Esas direcciones son ejemplos ficticios**, no el servidor de esta app.
Hay que sustituirlas por una URL real que entregue uno de los formatos
compatibles. No se ha validado la existencia de un catálogo de esta app
en esos formatos. `--url` necesita un valor: no hay endpoint predeterminado
ni búsqueda de direcciones en otros servicios. Para completar la descarga
automática solicitada hace falta la URL real o una versión que incluya ese
catálogo y permita identificar su flujo.

La descarga hace un GET con verificación TLS, timeout de 20 segundos y
límite de 32 MiB. No sigue redirecciones ni envía credenciales de cuenta.
No abre conexiones a los servidores VPN descritos en el JSON.

```python
from decoders.Python.vpn_plus_peru import decode, run

documento = decode(contenido_bytes)  # dict completo; lanza DecodeError
texto_json = run(contenido_bytes)   # str JSON o None; nunca usa la red
```

No se impone un máximo de cinco, seis ni mil servidores. Se conserva todo
el objeto JSON, incluidos arrays, campos futuros, payloads multilínea,
datos SSH/V2Ray/DNSTT y flags de importación. Los límites son de bytes y
complejidad del JSON, no de cantidad de servidores. No se interpreta un
objeto sintético con `servers` como prueba de un catálogo real.

## Formatos confirmados en el código

| Variante | Entrada | Derivación y cifrado | Autenticación |
| --- | --- | --- | --- |
| Legado, denominado v1 en las pruebas | Base64 de `IV[16] || ciphertext` sin prefijo `AKN1:` | PBKDF2-HMAC-SHA1, 1.000 iteraciones, 32 bytes; AES-256-CBC con padding PKCS#7 | No incorpora MAC |
| AKN2 | `AKN2:` + Base64 de `salt[16] || IV[16] || ciphertext || HMAC[32]` | PBKDF2-HMAC-SHA256, 12.000 iteraciones, 32 bytes; AES-256-CBC/PKCS#7 | HMAC-SHA256 de `salt || IV || ciphertext`, con la misma clave derivada |
| AKN3 | `AKN3:` + la estructura de AKN2 | PBKDF2-HMAC-SHA256, 15.000 iteraciones, 32 bytes; AES-256-CBC/PKCS#7 | Igual estructura HMAC, con material de contraseña distinto |
| JSON sin cifrar | Texto que empieza con `{` | Se conserva el objeto | Sin autenticación criptográfica |

En el legado, contraseña y salt son constantes del cliente. AKN2 reconstruye
su contraseña mediante XOR de segmentos embebidos. AKN3 reconstruye una
base de 43 bytes y calcula:

```text
material = base || SHA256(base || UTF8("AkuntVPN_v3_fixed_salt_2026_secure_key"))
password = UTF8(ISO_8859_1_decode(material))
key = PBKDF2_HMAC_SHA256(password, salt, 15000, 32)
```

La doble conversión de caracteres reproduce `new String(material,
"ISO-8859-1").toCharArray()` y `PBEKeySpec` de Java. Usar directamente los
bytes originales produce una clave distinta. Además, las rotaciones de
`byte` con signo del APK generan bytes no ASCII: el script conserva sus
resultados exactos, sin corregirlos a rotaciones ideales de ocho bits.

El parámetro `Context` de AKN3 no participa en esta derivación. Los flags
de dispositivo, caducidad, operadora o edición están dentro del JSON;
el lector los preserva para inspección y no ejecuta las políticas de
importación ni modifica configuraciones.

AKN2/3 verifican el HMAC **antes** de descifrar. No hay salida parcial si
falla. El legado carece de autenticación: padding y JSON válidos no prueban
que el archivo no haya sido modificado. Todos estos valores embebidos son
material del formato cliente, no credenciales de una cuenta del servicio.

## Validación y límites de la evidencia

- 13 pruebas específicas: tres versiones JCE, HMAC alterado en salt/IV/
  ciphertext/tag, codificación Java de la contraseña, versiones no admitidas,
  JSON completo, límites, CLI independiente y descarga simulada.
- Vectores sintéticos congelados producidos con OpenJDK/JCE. Su productor
  reproducible es `tests/golden/VpnPlusPeruVectorGenerator.java`.
- Los tres vectores se descifraron además con las clases `CryptoUtils*`
  extraídas del APK, compiladas localmente con adaptadores de `Base64` y
  `Context`. En sentido inverso, Python leyó las tres salidas producidas
  por esas clases a partir de un JSON sintético. No se ejecutó la aplicación.
- Prueba de preservación íntegra de un JSON sintético con 1.000 registros.
  No demuestra que este APK distribuya un catálogo de ese tamaño.
- **No se recibió una exportación `.gol` real ni se descargó un catálogo
  real de esta aplicación.** La paridad criptográfica se verificó con
  datos sintéticos y el código del APK; no se certifican otras versiones.
- No se añade `.gol` al registro del bot ni se modifica Android. El lector
  independiente queda disponible sin alterar las rutas anteriores.

```bash
python -m unittest tests.test_vpn_plus_peru -v
java tests/golden/VpnPlusPeruVectorGenerator.java > /tmp/vpn_plus_peru_vectors.json
cmp tests/golden/vpn_plus_peru_vectors.json /tmp/vpn_plus_peru_vectors.json
```

Límites: entrada de 32 MiB, profundidad JSON de 64 y 500.000 nodos. Rechaza
claves JSON duplicadas, números no finitos, Unicode inválido, prefijos AKN
desconocidos y longitudes incompatibles. Errores en `stderr`, JSON en
`stdout`; código 0 correcto, 1 formato/descifrado/descarga y 2 uso/E/S.

| Evidencia | SHA-256 |
| --- | --- |
| ZIP recibido | `4605ccf63965d942b0e3d5bc74caaa0d267c4e6283fc1aac46422c09f6357de4` |
| APK extraído | `9c8e537befde5935086c6661289dfc8693055930b433a6b6c9766960e247e591` |
| Vectores JCE sintéticos | `83dfe227cdb1935e3229bc464c7cacfc4a25b115b1a5d48d48c7d217ffe3e0ab` |

El APK y el código descompilado no se versionan. Solo se incluyen el lector,
esta documentación, pruebas y datos sintéticos.
