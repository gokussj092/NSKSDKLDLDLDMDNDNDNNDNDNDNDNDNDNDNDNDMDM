# Recetas y evidencia — AboWaged VPN 1.0 (1)

Análisis estático del APKS autorizado; sin ejecutar la aplicación, conectarse
a VPN, arrancar JNI/Android ni modificar el APK. Se consultaron solamente las
dos fuentes públicas exactas usadas por el código de actualización.

## Identidad reproducible

| Entrada | SHA-256 |
|---|---|
| APKS aportado | `8459fdac9860b2b1bb29c20a74f61b22fedf20d73dbcc1821d5af75a5fccda5b` |
| base.apk | `ff85b19319a4d36a899c2c344c923b42933933b3a517c5afe834d772db8d4266` |
| classes.dex | `312e9c50b639fed1328971f5e1583d6f8202d3ff11cce3adab61918fa2a91985` |
| classes2.dex | `27dcc8f56f5b8d335dd4cbafed0af1f8b7cae02748f3fae35d01beca4d7c126d` |
| ARM64 libwg-pro.so | `4334eee1a8743bb88aeb5effcf842807a67355210161899652b4d7513260c3dc` |
| res/raw/noobdev.js | `825380ee8a0898daf699d73d06098e968d0b0c2d74740a41cbc2d21b832489fe` |
| res/drawable/icon.png | `c54288a67e612f627d6fd00d553254d0f6f2184882a4c802dc263e9dc8eb1cf2` |

JADX 1.5.6: DEX 2 termina correctamente; DEX 1 informa **27 errores** generales.
Las funciones necesarias se inspeccionaron en la salida simple y en Dalvik;
no se considera ese resultado una descompilación perfecta. LSParanoid usa
`Deobfuscator$AboWagedVPN10$app`, `chunks/getString`, y el generador estándar
`RandomHelper`. La notación de llamadas entre DEX es
`Deobfuscator.AboWagedVPN10.app`. Herramienta: **2432 literales / 100 archivos /
2860 entradas de inventario**, datos privados fuera de Git.

## Formatos distintos

| Capa | Receta confirmada | Evidencia del APK |
|---|---|---|
| Catálogo exterior | Base64 estándar → XXTEA LE, delta `-1703701580`, `6+52/n` rondas, longitud final; clave literal truncada a 16 bytes | `AbstractC5137xE0.a`, `AbstractC0559Km.h/a/A`, `AbstractC4083qm.q` |
| Campos J | Base64 → AES-256-CBC/PKCS7, SHA-256 de constante nativa, IV fijo | `NoobCrypt.Jdecrypt/Jencrypt` → `AESCBCEncryptor`, `KeyGenerator`, `IVGenerator` |
| Archivo `.awg` exterior | Base64 → AES-256-CBC/PKCS7, IV cero; clave derivada de constante interna descifrada | `ExportActivity.t`, `AbstractC4083qm.r/p/s`, `AboWagedMain.R` |
| Campos F del perfil | Base64 → AES-256-CFB128/NoPadding, otra constante SHA-256, IV fijo | `NoobCrypt.Fdecrypt/Fencrypt` → `AESCFBEncryptor` |
| `Server` exportado | Cadena JSON con campos J; se preserva su tipo cadena | `ViewOnClickListenerC1135Vl.onClick`, `ExportActivity.t` |
| Selector UDP | JSON; `obfs`/`auth`: enteros decimales separados por comas → unidades UTF-16 Java | `AsyncTaskC3640o0.doInBackground`, `AboWagedMain.u` |

La clave XXTEA es el **texto literal** que parece una expresión Java
`new String(new byte[]{...})`; no se evalúa como código. El IV de campos es
`0123456789abcdef1032547698badcfe`. Las dos constantes JNI y la derivación
exterior están explícitas en `codec.py`, sin APK/SO en runtime.
No se reutiliza `_noobcrypt.py`: su formato Maya/XUI es CBC con IV transportado
y campos GCM, distinto de este. Tampoco se mezclan los deltas APNA/RENZ/Robust.

La tabla de campos es contextual: raíz, `Servers`, `Tweaks` y perfil usan
listas distintas. `Name`, `Flag`, `Info`, booleanos, números, valores nulos y
miembros desconocidos no se prueban a ciegas como ciphertext. El catálogo
inicial abre **35** campos J y el remoto **786**, incluidos textos vacíos
cifrados. No se seleccionan claves ni algoritmos por ensayo ante un error.

CBC/CFB/XXTEA de esta versión **no tienen tag de autenticación**. La validación
de Base64, longitud, padding, UTF-8 y esquema detecta errores pero no ofrece
autenticidad criptográfica ni garantiza detectar toda modificación.

## Contraseña y otros bloqueos

El flujo exacto es: construir JSON → incluir `isPassON` y `MyPass` → cifrar
con `AbstractC4083qm.r`, cuya firma solo recibe el JSON. En sentido inverso,
`AboWagedMain.R` deriva la misma clave fija, descifra y parsea el objeto antes
de comprobar caducidad, root, DeviceID, instalador y `isPassON`. La contraseña
del diálogo se compara después con `JSONObject.getString("MyPass")`.
Ninguno de esos datos se usa como secreto del cifrado. `MyPass` se conserva en
el resultado completo; no hay prompt ni dependencia del teléfono destinatario.

La propiedad `PublicKey` de un servidor corresponde a configuración de túnel
DNS, cifrada con J; no es una public key ECDH de destinatario como en NPVS.
Los usuarios/contraseñas de SSH/UDP son contenido del perfil, no parámetros
para abrirlo. `NoobLevel` controla credenciales durante la conexión; las
muestras usan nivel 0 y no se aplica esa transformación al JSON almacenado.

## Orígenes observados

Fuente principal fija en `C0365Gv.d`, consumida por `M.run` / `C2379gA1.g`:

`https://raw.githubusercontent.com/th3fre/Testing/refs/heads/main/Elk.txt`

Fuente adicional fija en `AsyncTaskC3640o0.doInBackground`:

`https://raw.githubusercontent.com/janatshaban/REMOTEUPDATER/refs/heads/main/pickerver`

El literal de respaldo `jezvpn.xyz` y `DefUpdateUrL` aparecen en preferencias,
pero el código de descarga observado abre **C0365Gv.d**, no ese valor. No se
registra una URL inferida ni se sigue el enlace de Telegram como catálogo.

| Fuente | Bytes cifrados/entrada | SHA-256 | Registros abiertos |
|---|---:|---|---|
| APK noobdev.js | 2600 | `825380ee8a0898daf699d73d06098e968d0b0c2d74740a41cbc2d21b832489fe` | 1 servidor, 1 ajuste, v1.0 |
| Elk.txt, HTTP 200, 2026-10-23 | 138664 | `2194c0d286b1a99067d49d07debf3ef2fc75a1f719a913676d231f110fe09c0f` | 12 servidores, 257 ajustes, v4.6.3 |
| pickerver, HTTP 200, 2026-10-23 | 790 | `f55faf4c41899b0b973b42a2eefb6bbe8b3a526cc3e2f715173b31708641ebef` | 2 UDP |

El broker solicita ambas fuentes fijas y transporta cada cuerpo completo en
Base64 dentro de `spdecode-abowaged-vpn-catalogs-v1`. El worker no accede a red.
Si falla cualquiera de las dos fuentes no se declara un catálogo completo.
El JSON combinado observado ocupa **102521 bytes**, muy por debajo del límite
existente de salida del worker; no se amplían presupuestos de otras apps.

## Herramientas y límites de la comprobación

`abowaged_native_oracle.py` ejecuta solo cuatro wrappers ARM64, con hash exacto,
10000 instrucciones por llamada y JNI de cadenas/call estático modelado.
Comprueba el destino Java, operación y clave de cada wrapper; no arranca JNI
ni ejecuta AES nativo: el APK delega esos cifrados a Java. JDK independiente
ejecuta las primitivas criptográficas y XXTEA; compara documentos completos.
`abowaged_verify.py` reproduce esa paridad sin imprimir configuraciones.

APK/SO, fuentes decompiladas, inventarios y catálogos reales permanecen fuera
de Git. Los fixtures publicados son sintéticos. Pendiente una exportación
`.awg` real; sin despliegue de VPS, compilación/publicación de APK o cambios C11.
