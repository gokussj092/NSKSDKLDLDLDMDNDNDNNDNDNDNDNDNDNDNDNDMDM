# Evidencia de HA Tunnel Plus 1.7.1

Muestra del 2026-10-26: `com.hatunnel.plus`, versión 1.7.1, code 76,
25 014 133 bytes. SHA-256:
`741e283ba3ee4b04b6988d5842d38491a51fa0bddfaf52d9c6bca9e6245ad051`.
Certificado SHA-256:
`b3ad016bcd4f267eac311aa37738811b4c959b9360f4edaf79eeb467cded9132`.
PNG original: 20 416 bytes, SHA-256
`42aa9743f5d430933257f0023af2182f2dcc6ae41a8930a9ca38e9f397ac3ab8`.

## Qué se recuperó

JADX 1.5.6 (checksum fijado por las herramientas del proyecto): DEX1 terminó
con siete errores; DEX5 sin errores. Los métodos relevantes de interfaz y
utilidades están en DEX1 bajo `app.fast.ssh`. `app.fast.ssh.core.*` no aparece
en el inventario estático examinado; no se considera recuperado el núcleo.
DEX2 contiene stubs Android, no la implementación de `VpnProfile`.
`ProtectedFastSSH` carga `libdexprotector.so`. Sus métodos nativos `s(String)`
y `a(Object,String)` resuelven cadenas y recursos protegidos. La entrada
launcher del manifiesto es `com.hatunnel.plus.jlvfyyvkjayic`; no usar el nombre
Java original como componente ADB.

| Recurso protegido | Bytes | SHA-256 |
| --- | ---: | --- |
| `servers.json` | 434 | `8068295899d9a388894295453c5bb89157883cadfc493c534f14017a3aa0cd5c` |
| `methods.json` | 279 | `982429da97191e834b09001307b29703455724a8f5bd9208ad2436facd86e529` |
| `customs.json` | 192 | `64a33644467f6596c9f0d0358faa9c5fef514bbfbb1573899089fdc12b4e0100` |
| `allowed_apps.json` | 579 | `03c6c163c646786871b8953f0583c871aac2bf3346c0826545a4a6e509ecdedd` |
| `whatsnew.json` | 309 | `ce33ef70020da09d388d75e6ed907a34234de3f84d3ab19d9d3aa5f3cd5723f8` |
| `assets.dat` | 2605171 | `ee2c1b923830b4278b91108982f475a6cdbab4999d481eff5bdbdc491233ea57` |

Primeros 16 bytes no son texto; las palabras LE siguientes son 1764, 956,
521, 2711 y 448. **No son recuentos de servidores ni tamaños de plaintext
validados.** No se ha demostrado el algoritmo de ese envoltorio. Una rutina
Java transforma el SHA-256 del certificado con dos tablas; usar su resultado
como AES-CTR/CFB no produjo un recurso verificable. Ese intento no es un codec.

## Consumidores y tokens protegidos

Los valores siguientes son argumentos de `ProtectedFastSSH.s`, expresados por
punto de código. Son ubicaciones para recuperar constantes, no sus valores.

| Consumidor | Token | Uso |
| --- | --- | --- |
| `ExportActivity.getContent` | U+2E60..U+2E6E | Secciones de perfil, descripción, flags, hashes y expiración |
| `ExportActivity.getContent` | U+2E6F | Frase para el cifrado exterior |
| `HomeFragment` | U+2EF0 | Frase para abrir `.hat` |
| `HomeFragment` | U+2EF3..U+2F08 | Perfil escondido, compatibilidad y sus campos |
| `MainActivity.processUpdate` | U+2F6B | Frase para `methods` remoto |
| `MainActivity.readLatest` | U+2F73 | Campo de versión del recurso |
| `AESEncryption` | U+3183..U+3189 | Digest, algoritmo, transformaciones y clave utilitaria |
| `DBHelper` | U+31A0 | Frase de la caché local |
| `ResourceUpdater` | U+31A6 | URL fija de GET de actualización |
| `XOREncryption` | U+31A7 | Clave XOR por `char` Java |

`AESEncryption` toma UTF-8 de la frase, aplica un `MessageDigest` protegido,
recorta a 16 bytes y construye `SecretKeySpec`; la transformación de `Cipher`
también está protegida. No inferir los nombres solo por el nombre de la clase.
`XOREncryption.xor_value_with_key` opera sobre unidades UTF-16 Java. El codec
histórico reproduce esa semántica para emoji, evitando el desplazamiento de
clave que causa iterar puntos de código Python.

El exportador sin protecciones guarda perfil y descripción. Si alguna está
activa, deja un perfil vacío, guarda `VpnProfile.hideParams(original)` en otra
sección y agrega `protextras` (anti-sniff, datos móviles, root, contraseña,
ID y fecha). Password e ID pasan por `AESEncryption.md5`. Finalmente cifra el
JSON entero con la constante de exportación. Falta abrir `VpnProfile` para
contrastar los nombres, campos y valores actuales; las claves históricas no
se atribuyen automáticamente a esta versión.

`ResourceUpdater`: Volley `JsonObjectRequest`, método GET, sin body.
`processUpdate`: obtiene `servers`/`allowed_apps` con `getString`, descifra
`methods` con otra frase y compara versiones con recursos/caché. La caché usa
otra frase. No reutilizar el lector `.hat` para los assets DexProtector ni
para todos los niveles del catálogo. `HttpTokenExchange` corresponde a
facturación, no autoriza un supuesto importador cloud.

## Android y límite comprobado

Se preparó la imagen oficial API30 x86_64 con SDK y checksums fijados en
`flexnet_emulator_probe.py`, sin KVM. El APK se instaló sin repack ni cambio de
firma. Hubo reinicios de `system_server` por watchdog: el log identifica
`UserDataPreparer.prepareUserData` / `UserController.finishUserUnlocking`.
La aplicación llegó a iniciar; la conexión Frida al PID agotó su tiempo de
espera. No se obtuvo una captura completa ni un vector del runtime original. No se
atribuye este fallo del sistema al cifrado de HA Tunnel, ni se afirma que la
aplicación haya rechazado Frida o exigido una cuenta.

`scripts/apk_analysis/ha_runtime_capture.py` conserva un camino acotado de
continuación: PID explícito, paquete/version y APK SHA exactos, cinco recursos,
solo constantes relevantes y oracle sintético. Sintaxis Python/JS revisada;
ejecución completa pendiente en Android estable. La emulación ARM64 parcial
del loader tampoco recuperó el núcleo: no se registra como descifrado exitoso.
