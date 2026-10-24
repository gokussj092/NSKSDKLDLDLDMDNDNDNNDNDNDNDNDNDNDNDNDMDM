# BD NET VPN PrinceBuild111 — evidencia

## Identidad

Paquete `dastan.prince.bdfreevpn`, versión PrinceBuild111, build 111.

| Componente | Bytes | SHA-256 |
|---|---|---|
| APKS proporcionado | 54646169 | `9cb27f404c603420104487ec2e53ac906eddd88be17a2fe579cef880ad79ff8d` |
| base.apk | 25465771 | `3f071ef3079ddabfc2e654303387f1a9f2ed07c3dcacaa3ae2a6221605491ada` |
| assets/gunny.json | 471448 | `d0b46dc31ed2db5d8e0e0904f15e06b58819d114a941c8db741ffff5288e870d` |
| libputils.so ARM64 | 3193912 | `4bdc6da41f0da29a9bbc9dc77a19c1e54f444f6e48a5a8deb44dbf0de51d7428` |
| res/drawable/ic_app_icon.png | 36294 | `46c3149a1e70087a9c34bc4b06b432ebd285b64762ab23ed4368d2cb4b7bce45` |

PNG original copiado sin modificar. JADX fijado por checksum: DEX1 termina
con 46 errores generales, DEX2 con 3 y DEX3 con 0. No se afirma una
descompilación completa. El APK contiene LIAPP; VPNClient/PUtils no tienen
definición recuperada en los DEX suministrados. No se arranca el APK ni se
ejecutan JNI, firma, identidad, attestation o red nativa para leer el formato.

LSParanoid `Deobfuscator$BDNETVPN$app` en DEX2: 787 llamadas resueltas en 35
fuentes; inventario de 2310 cadenas. DEX1 no tiene llamadas literales a esa
clase. Los helpers visibles, metadatos de archivo, inventario y SO permiten
confirmar los lectores aunque siga sin recuperarse el DEX protegido completo.

## Catálogo exterior

`Lnm;.a` contiene la constante `...|...`. `nm.b/c` descifra y `nm.d/e`
recifra el catálogo; `AbstractC0014s00.b` guarda el JSON editado con ese helper.
XXTEA delta decimal -1638454863 (`0x9E5729B1`), palabras little-endian de
32 bits, clave rellenada a 16 bytes y longitud original en la última palabra.
Coincide con el algoritmo de APNA/HX, confirmado independientemente para BD.

El asset abre 353579 bytes de JSON UTF-8, Version 57, 20 Free_servers y 257
Payloads. Tiene 18 secciones, incluidas HopPayload/DualConnectPayload/
SSLPayload, certificado, listas de hosts, rangos y flags. No se filtran.

`LKf;` contiene literalmente la fuente, también presente dos veces en el
inventario LSParanoid:

```
https://raw.githubusercontent.com/panigbatanc/BDNET2023/main/JSONDEC2025
```

GET a esa fuente respondió 200, 469153 bytes, SHA-256
`ee5fddae38dda803af62536b52f7656edc878ed1eeb613d07d622e45c95d8a27`.
Abre 351860 bytes exteriores, Version 56, 19 servidores / 255 Payloads.
El broker usa el identificador `BD NET VPN/PrinceBuild111` como User-Agent;
no se presenta ese header como recuperado del actualizador protegido.
No se infiere el resto del cuerpo de VPNClient ni se consulta otro origen.

El remoto publicado es anterior al asset: no se mezclan contenidos, se
renumeran versiones ni se anuncia que 56 sea la más reciente disponible
dentro del APK. Origen HTTPS literal, IPv4 pública fijada a TLS, límite 8 MiB,
reintentos transitorios y sin redirecciones. CLI: 25 s, 8 MiB y fuente fija.

## Archivos, texto y contraseña

Manifest registra `.bdnet`. El inventario recupera `.bdnet` y `bdnet://`.
`S00` construye tweaks con friendly_name, payload/host/sausage cifrados y
metadatos tweak_password, hwid_lock, tweak_expiry y flags. `B00.onClick`
divide el texto por el prefijo, llama `PUtils.pDecrypt`, crea JSONObject y
**después** lee `tweak_password` y abre `VPNClient.O`. La contraseña no deriva
la clave del formato. Se conservan todos los metadatos, sin aplicar sus
restricciones al visor. No se identificó un servicio de perfiles por token.

| Función ARM64 | Dirección | Bytes |
|---|---|---|
| pEncrypt | `0x147938` | 860 |
| pDecrypt | `0x147ef8` | 860 |
| stringToHex | `0x1462dc` | 524 |
| hexToString | `0x146560` | 376 |
| xorWithKey | `0x1466e4` | 548 |

pDecrypt pasa hexadecimal → XOR → NewStringUTF. La clave fija es
`4%PdXch>fkP]`: ocho bytes en `0xbfb77` más inmediato `0x5d506b66`.
Cinco casos ejecutados únicamente sobre el XOR ARM64 original coinciden con
el lector, con cadenas C++ modeladas y sin ejecutar controles JNI.

Se abren payload, host, sausage, server_host y los tres payloads globales;
CustomCert está preparado para el mismo campo cuando esté codificado.
Los demás valores, incluidos contraseñas/IDs con aspecto hexadecimal, se
conservan. Se observaron 187 textos cifrados distintos en cada documento.
Los campos mantienen sus tipos; los JSON guardados dentro de un string
se conservan como strings.

## UTF JNI y recuperación binaria

Hay secuencias no canónicas como `C0 B5` que representan el carácter `5`,
además de unidades sustitutas y NUL. La extracción se contrasta con el
decoder de unidades de `DataInputStream.readUTF`, no con UTF-8 que elimina
errores. Referencia primaria consultada:
[AOSP GetUtf16FromUtf8](https://android.googlesource.com/platform/art/+/9114f03/runtime/utf-inl.h).
Se implementa validación de límites y continuaciones; no se ejecuta código
de esa página ni del APK. Se acepta también UTF-8 ordinario de variantes
históricas; no se aceptan sustitutos aislados.

En cada catálogo hay una ubicación con bytes inválidos **después de un NUL**.
El valor visible es el prefijo de C-string que consume JNI, pero no se pierde
el resto: `_spdecodeBinaryFields` añade JSON Pointer, razón, sourceHex y
decodedBytesBase64 con los 195 bytes completos. Un error antes del NUL
falla; no se oculta con sustitución o `errors=ignore`. Las demás cadenas
válidas conservan incluso NUL internos como escapes JSON, aunque JNI pueda
terminar su interpretación antes. El resultado conserva más información
del almacenamiento que una llamada NewStringUTF sola.

La raíz reservada rechaza colisiones. La comparación independiente incluye
el documento entero y el anexo binario, no solo recuentos. XXTEA/XOR no
autentican el contenido: estructura válida no prueba integridad criptográfica.

## Integración y pendientes

PR #99 sobre Aura `5a5abe5`: proveedor público, PNG y control persistente;
mínimo 44 / 45 fichas, C0 240 / C8 252 y 24 overrides. `.bdnet` ya existía.
La función C0 genérica `xor_family.run` y sus fixtures se conservan; el bot
delega específicamente archivos/enlaces BD NET. Se admite JSON histórico
sin tweak metadata y se preservan los identificadores desconocidos.

No se cambian Android, novedades ni VPS. Herramientas bd_net_verify.py,
bd_net_native_oracle.py y referencia Java conservadas. Pendiente exportación
real `.bdnet` del build 111 y ejecución Android/Termux. Ningún fixture
sintético o catálogo sustituye esa muestra. APK/SO/DEX, catálogos y credenciales
reales permanecen fuera de Git.
