# Análisis reproducible de CREEB INJECTOR 38.0

APKS autorizado; paquete `com.creeb.Injector`, versionName **38.0**,
versionCode **40**. Sin ejecutar el APK, conectarse a un túnel, enumerar
Firestore ni modificar la aplicación. Fecha del análisis: **2026-10-23**.

| Entrada | SHA-256 |
|---|---|
| APKS, 51686462 bytes | `61e6745278113a2aed2b1fc309c837e72b0b5ce95d27061d075dad26f788e9b0` |
| base.apk | `20f665a10d8c31996d454f4d07a0422cd45061c6cba0ad37e05202f086d51fed` |
| classes.dex | `6f1b63fe0b25abd3b40945e6eeb6838220ac8027f55ad8073de8b811b0a400b2` |
| classes2.dex | `0230751b246ca98831cc0598931fdd00aee4314135bc5eae490077ae86795989` |

JADX 1.5.6 terminó con **62 / 4 errores** generales en DEX 1/2. No se afirma
una descompilación perfecta. La clase anónima de la clave no salió como Java
utilizable: se leyeron directamente sus **64 instrucciones Dalvik** con
`dex_method.py`, sin ejecutar código del APK.

## Archivo individual

`ConfigParser.FILE_EXTENSAO` es `creeb`. `convertDataToFile()` almacena los
campos en `java.util.Properties`, llama `storeToXML(...,"Configuration File")`
y escribe `encodeInput()`. Esa función llama `Cripto.encrypt(KEY_PASSWORD,...)`.
`decodeInput()` llama a `Cripto.decrypt` y después `Properties.loadFromXML`.

`Cripto.encryptOrDecrypt()` crea `DESKeySpec(key.getBytes())`, obtiene una clave
con `SecretKeyFactory("DES")` y usa `Cipher("DES")`: DES-ECB/PKCS5 en la receta
reproducida por el oracle JDK. El archivo son los bytes cifrados directamente,
sin Base64, IV transportado, salt ni una KDF de contraseña personalizada.

`ConfigParser$1.toString()` construye **CREEBINJECT** mediante enteros Java y
desplazamientos sin signo; `DESKeySpec` consume los primeros ocho bytes:
**CREEBINJ**, hex `4352454542494e4a`. Las once parejas `(entero,shift)` están
transcritas en `tests/golden/creeb_oracle.java`; su operación se contrasta con
el volcado Dalvik. No se ensayan variantes ni claves de `.crev`.

Los campos exportados se obtienen de `SecurePreferences.getString`, ya abiertos
por la app; no llevan la capa de cifrado del almacenamiento privado local.
El lector conserva también campos desconocidos, campos vacíos y cualquier
JSON/protocolo que vaya como texto dentro de Properties.

`raw_xml` conserva el XML exacto. `entries` conserva todas sus entradas; el mapa
`properties` reproduce la semántica de `Properties.loadFromXML`, incluida la
última aparición de una clave. Se normalizan los saltos XML en ese mapa como
JDK; las referencias numéricas `&#13;` mantienen CR. Los pares de referencias
UTF-16 emitidos por Java, como `&#xd83d;&#xde00;`, se combinan antes de usar el
parser XML estándar, manteniendo intacto `raw_xml`. Se rechazan referencias
surrogate aisladas, entidades y DTD personalizados. Nunca se descarga el DTD.

DES no tiene MAC/tag: padding, UTF-8 y esquema detectan errores de formato,
pero no autentican criptográficamente el contenido ni detectan toda alteración.

## Bundle actual con varios perfiles

`ConfigExportFileActivity` escribe directamente los bytes UTF-8 de
`TunnelProfileStore.serializeProfilesBundle()`. Este genera:

```json
{"type":"creeb_profile_bundle","version":1,"profiles":[{"id":"...","name":"...","hostPort":"...","tunnelType":1,"prefs":{},"isImported":false,"isProtected":true}],"security":{}}
```

`security` y `message` son opcionales. `MainActivity.handleImportConfig` y
`proceedWithImport` detectan primero `isProfilesBundleJson`; si no es un bundle,
usan `ConfigParser`. El lector admite esas dos rutas y entrega todos los
perfiles; no selecciona únicamente el primero ni elimina los atributos.
Para un bloque DES cuyo primer byte coincida con `{`, una prueba JSON fallida
no lo excluye si mantiene la longitud DES correcta. La única clave DES es fija.

## Bloqueos separados del cifrado

`ConfigParser.checkConfigSecurity()` llama **primero** a
`loadFromXML(decodeInput(...))`; después extrae `file.proteger`,
`file.pedirLogin`, `file.passwordHash`, `blockHwid`, `hwidstring` y paquetes
bloqueados. `validatePasswordWithHash` compara SHA-256 de la contraseña del
diálogo con el hash leído. `KEY_PASSWORD` no recibe ninguno de esos valores.

En bundles, `getProfileBundleSecurityOptions/Validation` lee `security` de un
JSON ya abierto. `requiresPassword/passwordHash` controla la importación.
Por tanto **este decodificador no requiere contraseña ni HWID externos**.
Se conserva el hash, no se afirma recuperar la contraseña original ni se
efectúa ningún intento de adivinarla. Las credenciales de SSH/UDP/WireGuard son
contenido del perfil, no secretos de entrada del contenedor.

## Catálogo y referencias remotas

Se revisaron recursos/assets, rutas de importación/exportación, lista local de
perfiles y actualizadores. `assets/v2ray_config.json` es una plantilla; las
bases geoip/geosite no son listas de servidores del proveedor.

`model.UpdateAsync` contiene la URL fija:

`https://bitbin.it/CCOuleAK/raw/`

La respuesta observada tiene **339 bytes**, SHA-256
`776ba5ec2bf28204e5f246bc31b72a3d0a568f45bfbd995300ab4c4c631958b3`, con
`newVersion:"16.0"`, `apkUrl` y `versionNotes`. Contiene saltos literales dentro
de la descripción, por lo que no pasa JSON estricto. Su contenido es una
actualización de aplicación, no servidores; no se descarga ni ejecuta ese APK.
No se usa como evidencia de un catálogo descifrado ni de versión 38 actual.
`util.AppUpdater` tiene una URL vacía en este APK.

`getResults()` / exportación Cloud usa documentos Firestore `cloud_configs`
referidos por tokens `CREEBINJ-...`. No es un feed público general. No se
enumeran documentos ni se usa un token ajeno. No hay adaptador Server VPN
registrado para esta app: **catálogo no identificado**, pendiente de aportar
una fuente de servidores verificable si existiera.

El antiguo `decoders/Python/crev.py` sigue igual: XXTEA, sufijos `.crev`, `.cer`
y `.cerv`; no se deduce compatibilidad con él por compartir el nombre CREEB.

## Recuperación y alcance

`inspect_apk.py`, `decompile.py`, nuevo `dex_method.py`, `creeb_verify.py` y el
oracle/golden sintéticos están versionados. No se requieren SO/Unicorn para
este formato. Binarios, fuentes JADX y respuesta remota real quedan fuera de
Git. Cinco documentos sintéticos iguales al worker; tres DES/XML iguales a
JDK completo. Falta una exportación `.creeb` real. No se han desplegado estos
cambios, publicado APK, modificado Android ni novedades C11.
