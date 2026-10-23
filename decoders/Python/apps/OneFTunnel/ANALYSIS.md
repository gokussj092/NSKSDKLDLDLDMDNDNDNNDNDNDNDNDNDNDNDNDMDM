# Formato y recuperación del análisis

APK autorizado: 1FTunnel 0.6.99, build 125, paquete `com.oneftunnel.app`.

| Fuente | Bytes | SHA-256 |
|---|---:|---|
| APK | 29098602 | `8a2478a05487e8d2928e7341e8b9961f5d62755ceca6f6517a9da98e0fc57c5c` |
| classes.dex | 2440040 | `1b590b553d2cd497df47da9feacfac4725f11baaece638a719fbbf3e01c2baca` |
| classes2.dex | 197160 | `4b456639e17b165d8a0f3bc8f4682ad17bd14e1a46e2e41170ee3df53782adfd` |
| liboneftunnel-security.so ARM64 | 915016 | `b46e85425e6512a39bd5fde5cd5037bef7ed065ab27c704b96ce40aa3a24e0ff` |
| .1ftnl real aportado | 2904 | `4826e096a2418f1db80559c4c85a090bf56a8e7ac5df738532d7cb3f58685694` |

`inspect_apk.py`, JADX 1.5.6 y `elf_inspect.py` se conservaron previamente y
se reutilizan. `u2.f` escribe/importa el documento; `u2.e` serializa UTF-8
con longitud i32 BE. `NativeSecurity` importa JNI. Análisis relevante completo
en DEX1; JADX informa 17 errores generales de reconstrucción ajenos a esos
lectores. DEX2 termina con código 0. Un SIGBUS de PerfMemory del JDK de este
entorno se resuelve con `JAVA_TOOL_OPTIONS=-XX:-UsePerfData`.

## Contenedor

Los prefijos de texto eliminan cuatro bytes de magic antes de codificar en
Base64 URL-safe. El lector repone `1FT1`. El formato binario es:

`magic4 | versión1 | algoritmo=1 | KDF=1 | reservado=0 | salt16 | nonce12 |
aadLength:u32be | cipherLength:u32be | AAD | ciphertext+tag16`.

Límites del importador: 393216 caracteres Base64; envelope nativo 5 MiB;
AAD 1024 bytes y ciphertext 4 MiB + tag. Longitudes exactas, sin sufijos libres.
Cloud mantiene además sus cuotas globales (texto 250000 caracteres y salida
4 MiB). El lector no amplía límites de otros formatos.

AAD: versión u8, paquete y certificado con longitud u16be, configVersion u32be;
desde v2, keySlot u32be, mínimo build i64be y createdAt i64be; después expiry
i64be, tipo u8 y bloqueo u8; desde v3, blockRoot bool. Versión interior y
exterior deben coincidir. El certificado debe ser uno de los dos fingerprints
incluidos en el formato de la app. No son credenciales HTTP.

El root de formato reconstruido por ambas ranuras es el mismo, incorporado
como material de interoperabilidad en `codec.py`. Contraseña no vacía:
`IKM=HMAC(root, "1FT1 password vN" || UTF16BE(password))`; sin ella, IKM=root.
`PRK=HMAC(salt,IKM)`; clave de 32 bytes:
`HMAC(PRK,"1FT1 HKDF AES-256-GCM vN" || rawAAD || 0x01)`.
N=1 para contenedor v1; N=2 para v2/v3. AES-GCM autentica rawAAD exacta.

## CFG1

`magic4 | versión:u8 | id:str | name:str | createdAt:i64be | message:str? |
fieldLockMask:i32be(v2+) | hasSSH:bool | SSH? | hasInject:bool | Inject? |
hasDNS:bool | DNS? | hasXray:bool | Xray?`.

Strings: longitud i32be de bytes UTF-8, máximo 2 MiB; -1 solo donde sea nullable.
Booleanos 0/1 estrictos, enteros BE. Mask -1 equivale a null; valores 0–511.

- SSH: host, puerto i32, usuario, contraseña.
- Inject: enum, payload?, proxyHost?, proxyPort i32(-1=null), sni?, wildcardHost?.
- DNS: primaria y secundaria.
- Xray: protocolo, host, puerto, uuid?, password?, seguridad, transporte,
  path?, serviceName?, sni?, hostHeader?, wildcardHost?. v3 añade allowInsecure
  y alpn?; v4 flow?, fingerprint?, realityPublicKey?, shortId?, spiderX?;
  v5 mode?. `codec.py` conserva el orden y todos los enums observados.

Se exige EOF exacto, ID/nombre no vacíos, createdAt concordante con AAD v2+ y
sección/protocolo compatible con configType. No se usa la caducidad de la
política como sustituto de autenticación GCM. La muestra real tiene envelope
2177 bytes, AAD 122, ciphertext/tag 2011 y CFG1 v3 de **1995 bytes**, consumidos
íntegros, **ocho strings**. Máscara 366; sección Xray, sin SSH/inject/DNS.
No se publican los campos privados del perfil.

## Funciones ARM64 conocidas

| Función | Dirección |
|---|---|
| JNI encrypt / decrypt | `0x625f0` / `0x65738` |
| parser envelope / AAD | `0x677d4` / `0x6b5d4` |
| KDF / callback HMAC | `0x6432c` / `0x6a7ec` |
| AES-GCM vía JNI | `0x64d04` |
| parser CFG1 / objeto Java | `0x67a44` / `0x680dc` |
| validación identidad/versión | `0x63b88` |

`oneftunnel_native_oracle.py` verifica el SHA exacto y ejecuta la KDF original
en Unicorn: reconstrucción NEON y composición HKDF originales; callback Java
HMAC modelado con host HMAC. Solo helpers de memoria y asignación acotados;
sin Android, JNI real, red o arranque de la app. No se atribuye a este oracle
la ejecución nativa del parser ni de GCM: esas rutas se contrastan con JDK.

## Catálogo y alcance

Inspección de assets, código de app y URLs de fuentes ofuscadas: solo
`assets/dexopt/baseline.prof` y `.profm`, comprobador de IP `api.ipify.org` y
enlaces de Telegram/ayuda. No se encontró lista ni endpoint de actualización
de servidores. Esto limita el alcance del análisis estático; no demuestra que
ninguna versión pueda tener catálogo. Pendiente si aparece otra fuente.
No se hacen consultas remotas ni se reutilizan identidades para simular la app.

APK, SO, fuentes descompiladas, inventarios y perfil real/descifrado se guardan
fuera de Git. Los scripts y referencias bastan para repetir las comprobaciones
cuando se vuelvan a aportar los binarios con estos hashes.
