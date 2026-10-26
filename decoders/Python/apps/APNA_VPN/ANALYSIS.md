# APNA VPN 3.9 — evidencia y recuperación

## Identidad del archivo proporcionado

- Paquete: `my.teamapna.tunnel`, versionName 3.9, versionCode 30.
- APKS SHA-256: `47df5cbfcb5f6fa42895ce5d049ac27698963618338c2e0094dfd280db5fd317`.
- base.apk SHA-256: `46fabbf6d2db516c5b518a34ea13ca5347ae8f29d017239142b137747693cde4`.
- `lib/arm64-v8a/libputils.so`: 3193936 bytes, SHA-256
  `f5198b3d5efa4bd446a18e4c12357ed8dcff3df072b62596526cc4152225bd45`.
- Icono de `res/drawable/ic_app_icon.png`, copiado sin modificar: 21812 bytes,
  SHA-256 `01b38d6d006d24b6d50d3e32b3595bbdcd6bb0d634f2468ce3a009bd7cd966ee`.

Se usan ZIP, DEX, JADX fijado por checksum, LSParanoid y ELF/Capstone. No se
ejecuta el APK ni las funciones JNI de firma/identidad. El oracle ARM64 ejecuta
únicamente `xorWithKey` con memoria acotada y operaciones de cadena C++
modeladas; no ejecuta Android, JNI, autenticación ni red.

## Catálogo y actualizador

`Lprince/open/vpn/activities/a;.g()` lee `filesDir/janu.json` o el asset.
`LHZ.o` aplica Base64 y `LBm.c/b` hace XXTEA modificado. La clave fija de
`LBm.a` es `b"...|..."`, rellenada con ceros a 16 bytes, delta `0x9E5729B1`,
palabras little-endian de 32 bits y longitud original en la última palabra.
Se recuperaron cadenas LSParanoid de cinco bloques de
`Deobfuscator$APNAVPN$app`: 889 sustituciones en 40 archivos y 1223 cadenas
en el inventario. El DEX y la referencia Java respaldan el algoritmo.

`OpenVPNClient.r()` construye `YV`, una petición Volley GET con headers propios
vacíos, para la fuente literal activa:

```
https://paperonboard.com/updater/3c3c4c58d864ca394da16656b4d0c4
```

El `UpdaterLink` guardado en el catálogo incluido apunta a
`https://amtun.xyz/updater/c44cef4d43f71b0d45e01ae1dc7bd2` y devolvió 403.
No representa la llamada del actualizador de este APK. El GET activo con agente
Python también devolvió 403; con `User-Agent: Dalvik/2.1.0` y
`Accept-Encoding: identity` entregó 200 y un catálogo descifrable. Ese agente
mínimo reproduce la familia del agente de plataforma HttpURLConnection; no
se presenta como una constante textual del APK.

El asset tiene 281096 bytes Base64, SHA-256
`620e4aa2cd5c4ec6cb1d2015b4bfdec172050bcdb8e1b5e4187f026563e5a94a`.
Entrega Version 289, 19 Free_servers, 491 Payloads y 210815 bytes UTF-8. El
remoto validado el 2026-10-24 tiene 278008 bytes Base64 y entrega Version 456,
18 Free_servers, 493 Payloads y 208498 bytes UTF-8. Ambos tienen diez secciones;
las otras tres listas de servidores están vacías. Se comparan documentos
completos, sin filtrar campos ni guardar contenido real en el repositorio.

El broker solo permite el origen HTTPS literal, resolución a IPv4 pública
fijada a TLS, límite de 8 MiB y reintentos transitorios existentes. No sigue
redirecciones ni enlaces incluidos en documentos descargados. La CLI aplica
GET fijo, 25 segundos, sin redirecciones y lectura acotada a 8 MiB.

## Archivos y texto

El constructor de `OpenVPNClient` establece `.apnavpn` y `apnavpn://`.
`E(String,JSONObject)` exporta con `PUtils.pEncrypt(Context, json.toString())`;
la interfaz permite copiar y guardar el resultado. La importación de archivo
y de intent VIEW llama a `PUtils.pDecrypt` y construye un JSONObject **antes**
de consultar `tweak_password`. El diálogo posterior no modifica la criptografía.
No se identificó un servicio cloud de perfiles por token.

La biblioteca ARM64 exporta `pEncrypt` en `0x147924` y `pDecrypt` en `0x147c58`.
La ruta útil es `stringToHex` (`0x1462c8`) / `hexToString` (`0x14654c`) y
`xorWithKey` (`0x1466d0`). La clave de doce bytes es `b"4%PdXch>fkP]"`:
ocho bytes en rodata `0xc46ec` más el inmediato little-endian `0x5d506b66`.
`my.teamapna.tunnel` es una comprobación de identidad JNI y no un KDF. No se
deduce AES de las funciones OpenSSL enlazadas que esta ruta no utiliza.

`GetStringUTFChars`/`NewStringUTF` implican UTF-8 modificado JNI. El lector
combina pares UTF-16 sustitutos para caracteres suplementarios y entiende
NUL modificado; también acepta UTF-8 ordinario válido. Rechaza hexadecimal
impar/no válido, JSON duplicado/no finito, profundidad excesiva, sustitutos
aislados y perfiles sin `friendly_name`/`tweak_password` de tipo string.
Conserva todas las restricciones y campos originales. La entrada se limita
a 8 MiB; el transporte de texto del worker tiene además su límite vigente.

La clave se contrastó con cinco casos de la función original ARM64: cadena
vacía, JSON corto, límite SSO, cadena larga y perfil. Los perfiles sintéticos
con y sin contraseña, Unicode y restricciones coinciden íntegros con Java y
los workers de archivo/texto. Esto **no certifica una exportación real**:
esa muestra y la ejecución Android siguen pendientes.

## Herramientas conservadas

`scripts/apk_analysis/apna_verify.py` compara el JSON completo con JDK y worker;
`--file` añade las rutas de archivo y texto. `apna_native_oracle.py` verifica el
XOR original y exige el hash exacto del SO. `tests/golden/apna_oracle.java`
implementa XXTEA y usa `DataInputStream.readUTF` para la referencia JNI; su
perfil de prueba tiene el límite writeUTF de 65535 bytes, distinto del runtime
Python. Ver comandos de recuperación en `scripts/apk_analysis/RESTORE.md`.
