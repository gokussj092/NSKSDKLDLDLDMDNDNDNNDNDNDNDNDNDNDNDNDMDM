# HTTP SocketClay 3.4.0

Paquete `com.socketclay.http`, versionCode **341**. Lectores Python para el
servidor Cloud de SP-DECODE; no necesitan APK ni bibliotecas nativas al ejecutar.
Trabajo en `feat/austroplus-vpn-13-0-1-decoders`, PR #96.

## Estado real

- Catálogos incluidos en el APK: **JSON completo comprobado**, 1 servidor y
  2 entradas de usuarios. Estas cifras describen las copias incluidas, no la
  fuente remota actual. Una entrada de usuarios contiene configuración interna;
  el lector conserva todas las entradas sin ejecutar sus contenidos.
- `.sks`: importador GCM y DES confirmado por código y vectores Java sintéticos.
  No se proporcionó una exportación real independiente ni se certifica writer.
- Worker Cloud: ID fijo `http-socketclay`, ejecución aislada y sin red.
- Catálogo público mínimo **14**, tarjeta con icono original y `decodeEnabled:false`.
  **La descarga remota no está habilitada ni certificada.**
- La revisión automática rechazó consultar las fuentes externas de servidores y
  usuarios por su posible contenido de credenciales. Hace falta autorización
  explícita antes de volver a intentar esas consultas. No es un fallo de lectura
  del ZIP ni del entorno de ejecución.

## Uso local

Python >=3.10 y `pip install -r requirements.txt`. Dentro del repositorio las
carpetas hermanas ya están presentes. Al copiar este lector aparte, conservar
`HTTP_SocketClay/` y `HTTP_FenixVPN/codec.py` + `field_names.json` juntos.

```bash
python file_decoder.py perfil.sks > perfil.json
python file_decoder.py < perfil.sks > perfil.json
python server_catalog_decoder.py catalogo_cifrado.txt > catalogo.json
python server_catalog_decoder.py --stdin < catalogo_cifrado.txt > catalogo.json
```

El lector acepta copias locales de servidores o usuarios y conserva las claves
originales, tipos, listas, metadatos, campos vacíos y secciones desconocidas.
`run(data: bytes) -> str` nunca descarga datos. No interpreta ni ejecuta enlaces,
comandos, nombres de clases o configuraciones presentes en el resultado.

`--download` es una opción explícita de la CLI para **la fuente fija de
servidores** extraída de `SkProtect.updateURL`; no admite URL de entrada ni
catálogo remoto de usuarios. Solo acepta HTTP 200 sin compresión y bloquea toda
redirección. Su respuesta real y la cadena de redirecciones siguen pendientes;
esta opción no acredita disponibilidad remota. No se añadió el proveedor al
broker HTTP público para evitar presentarlo como operativo antes de comprobarlo.

## Método actual del catálogo

1. `Configs.loadConfig` abre `assets/flags/us.png`, busca `WKCFGSTART` y pasa
   el contenido posterior a `ooOoO.o0oo0o00.o0oooo00`. En `libconscrypt.so`,
   JNI `0x3d2e8`, esto es nonce de 12 bytes, ChaCha20-Poly1305 IETF sin AAD,
   ciphertext y tag de 16 bytes. La clave fija está en `0x13d2c`.
   Así se recuperaron los parámetros de esta compilación, no datos de usuarios.
2. Los catálogos actuales están en `assets/flags/config.png` y `usr.png`.
   Son texto Base64 de `WakkoDev || salt8 || AES-256-CBC/PKCS7`.
   `com.google.webview.AES` deriva clave/IV encadenando MD5 del bloque anterior,
   contraseña `NIGHT_MODE` en UTF-8 y salt, hasta 48 bytes. No usa PBKDF2.
3. `libcrypto.so`, JNI `oOoOoOoOoo` en `0xd9c40`, recupera la constante de
   compilación mediante el callback Java `o0oo00o`. Calcula SHA-256 de
   `constante || Version` y convierte los primeros 16 bytes por módulo 62 al
   alfabeto `A-Z a-z 0-9`. `AESED` completa esos 16 caracteres con ceros hasta
   32 bytes. La receta Java `generateNaju` visible en `Configs` no es la llamada
   que utiliza el constructor; no se tomó como sustituto del método nativo.
4. Los campos registrados en `field_names.json` usan URL-Base64 → ChaCha
   autenticado → URL-Base64 → IV16/AES-256-CBC/PKCS7 → rotación Java de letras
   `26 - INPUT`, donde `INPUT=7`. Se respeta UTF-16 y `Character.isLetter`/
   `isUpperCase`, no una rotación ASCII de todo el JSON. También se cubre
   sintéticamente la forma AES directa de `AESED`, sin el envoltorio nativo.
5. Fuentes de los 27 campos de servidor: `com.google.webview.Servers`,
   consumidores de nombre/información/bandera y sus recursos Android. Los siete
   campos de usuarios incluyen **Name cifrado**, distinto de HTTP FenixVPN.
   Los campos opacos conservan sus nombres, sin inventar alias.

La selección entre campo directo y envuelto se realiza por su longitud antes
de descifrar. Un tag ChaCha fallido nunca dispara un reintento CBC.
Las listas de servidores/usuarios se abren usando su propia `Version`.
La combinación de credenciales incrustadas en servidores con una versión
independiente del catálogo de usuarios no está certificada; las dos copias
incluidas observadas tienen versión `1`.

`SkProtect` contiene también rutas antiguas para `flags/zs.png` y `cy.png`.
No se confunden con los catálogos actuales de `Configs`, ni se anuncia soporte
para esos catálogos heredados. No se identificó un esquema propio de enlaces
de importación que justifique un tercer lector.

## Archivos .sks e integración

`com.socketclay.sshservice.config.ConfigParser` confirma `FILE_EXTENSAO=sks` y
`Cryptor` con `fubvx788b46v`: PBKDF2-HMAC-SHA256, 1000 iteraciones, salt32,
clave de 128 bits, nonce12, tag16, sin AAD. El mecanismo legado usa DES-ECB con
los primeros ocho bytes de `cinbdf665$4`. `convertDataToFile` produce XML Java
Properties; se preservan claves duplicadas, orden, vacíos y `raw_xml` completo.
Estos parámetros coinciden con el motor de HTTP FenixVPN: se reutiliza y la
selección histórica SocksIP JSON `d`/`v` permanece intacta. No se cambia la matriz
C0, no se añade otra extensión `.sks` ni código de descifrado Android.

Límites: archivos 5 MiB, catálogo/salida 8 MiB, profundidad 64. Se validan tags,
padding, forma del JSON, límites y claves duplicadas. El sobre CBC exterior no
tiene autenticación propia; no se afirma una garantía que el formato no ofrece.
Los errores CLI/worker no imprimen valores de entrada ni resultados parciales.

Icono: PNG original exacto, recurso `0x7f080142` de `split_config.xhdpi.apk`,
431×426, 71943 bytes. Hash y procedencia en `manifest.json`.
No se incluyen APK, `.so`, catálogos reales, resultados o credenciales reales en
Git. Las constantes del lector son parámetros fijos de la compilación analizada.

## Para completar la habilitación remota

Tras obtener autorización explícita para consultar la fuente externa:

1. Consultar el endpoint original de servidores y comprobar HTTP, límites,
   formato y cada redirección. No aceptar orígenes arbitrarios de Dropbox.
2. Comparar todo el JSON con el oracle independiente, revisar versiones y
   confirmar que no quedan campos conocidos sin abrir.
3. Registrar una fuente HTTPS fija verificada en `server-vpn-provider.mjs`,
   con DNS/IP fijados y redirecciones restringidas; probar los controles de
   proveedor, cambiar `remote:null`, actualizar versión de catálogo y pruebas.
4. Mover la entrada al registro de Servidores VPN confirmados. Preparar novedades
   solo cuando el usuario las solicite. Una integración en Git no despliega la VPS.

Ver `TESTING.md`, `manifest.json` y `docs/cloud/CATALOGS_UPDATE_RUNBOOK.md`.
