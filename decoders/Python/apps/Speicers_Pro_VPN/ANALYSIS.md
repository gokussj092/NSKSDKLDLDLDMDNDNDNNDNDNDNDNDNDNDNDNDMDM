# Reinvestigación de Speicers Pro 104.1.20/build123 — 2026-11-01

Google Play anuncia Version123 (actualizado28-oct-2026). XAPK obtenido de
APKPure, paquete/netfree.mx.store y104.1.20/code123 comprobados en AndroidManifest.
Se completó una descarga parcial mediante Range; ZIP y CRC completos correctos.
XAPK40752825 bytes SHA256:
`e3c46d1b467b16647c2546cb8525a4fc0c6258c2c79b9bca9f9ef4715d42d09d`.
Base APK SHA256 `b064d225c6a7c150d922057ad1304886b3dd3100b07d3d19a85057c0f4918427`.
Certificado SHA1 `2efc2d2925f21963455e4e55994f9d810f45b707`,
SHA256 `0df454e6429e1e131aff6f49e1337cb5ef4c1abcd87427d22a5258c07f6d8c9e`.
Launcher netfree.mx.store.SplashActivity. DEX SHA256
`46a5a731c24b0bc0cd0479cd519a6d3f1a81dc96fa25cafd54888435ea66c1e4`.
JADX1.5.6:18 errores generales; no es una descompilación completa.

## Método nuevo recuperado

`pUiqFaC0z1g3yNQA.BOwrZmfITwTJm50`: prefijo SPCF1 LF, JSON exterior
{payload,signature,alg}. RSA3072 PKCS1v1.5 SHA256 verifica el ASCII del payload
Base64URL con la clave pública del APK; no se usa una clave privada del proveedor.
Payload v1/app netfree.mx.store/kind servers_file/format SPCF1,
key_id a8d4e7d79e33bcb8 y600000 iteraciones exactas.

`oEPOtrv5uGtfWoMYzqE`: XOR de dos tablas públicas32 bytes → clave HMAC.
HMAC-SHA256 de `SPEICERS_FILE_PASSWORD_V1` +NUL+ frase LICENSE:NIGHT_MODE;
Base64URL sin padding del digest es password ASCII de PBKDF2-SHA256/600000/256.
Salt32, nonce12, AES-GCM/tag16. AAD ASCII:
`SPCF1|netfree.mx.store|servers|<key_id>|600000|<salt Base64URL original>`.
No se alteran firmas o tags; un error autenticado no cae al lector antiguo.
La frase y las claves interiores del build120 siguen coincidiendo. Tras abrir,
se descifran todos los campos interiores, conservando metadatos/flags/unknowns.
Las constantes publicadas son del formato de la app, no secretos de sesión.

`Uw7kqwPItX8IYS7mRB7.REhg2Fdx8QoajncCp` usa GET al manifiesto fijo
`https://gen.spei.click/updates/servers.json`, límite16000 bytes.
`gIigaNpNFxBVoAoGPyqEVD.NsgL2JskSlda` verifica su misma firma RS256.
Se exige v1/app/kind server_update/origin https://gen.spei.click/format SPCF1,
min_app_code121. Versión decimal sin ceros iniciales,1..2147483647,
sha256 hex64, size1..3000000 y count0..10000. URL exacta reconstruida:
`https://gen.spei.click/updates/servers/<version>/<sha256>.png`.
Segunda descarga sin redirecciones, valida tamaño/hash y firma/SPCF1, después
igualdad de Version y número de Servers. Accept y Cache-Control originales
recuperados, sin autenticación/sesión adicional. No se eligieron otras rutas.

## Evidencia real y bloqueo observado

| Entrada real | Resultado completo |
| --- | --- |
| APK123 assets/flags/config.png,141487 bytes | Firma original y GCM válidos, versión1,73 servidores,799 campos |
| APK123 assets/config/config.json,96000 bytes | Glifos anterior, versión9,32 servidores |
| GitHub histórico servidores_pro,105132 bytes | versión35,74 servidores,797 campos |

Los tres documentos enteros coinciden con JCA, CLI/lector y worker aislado;
ningún perfil, bandera, campo desconocido o servidor se recorta. El resultado
incluido no demuestra descarga del nuevo feed. La referencia JCA123 es
`tests/golden/Speicers123Oracle.java`, independiente del Python.

Fuente histórica descargada por Goku desde el repositorio del proveedor,
commit f065becde43a99b4e33632808a5d5cf936f567dd, blob
`a7807d8e77336a4b86497288e719cc3e8f538ba4`; SHA256 cuerpo
`713af873fc262136f9a51302f1119e6e09d10e5386a9e1fbe9e4054b25d16d16`.
Se conserva como evidencia histórica, sin presentar como respuesta123.

**Feed123 NO validado:** Python timeout al pedir el manifiesto; curl con
cabeceras Android terminó HTTP000/0 bytes, exit28,
`Proxy CONNECT aborted due to timeout`. La búsqueda web directa también lo
marcó inaccesible. No hay respuesta HTTP del origen ni evidencia para afirmar
que el servidor esté caído o que rechace claves/cabeceras. La CLI nueva real
falla sin producir JSON. No se recuperó su manifiesto ni el archivo remoto.
El broker preexistente conserva el origen histórico y no se activa el nuevo.

## Archivos y Unlocked

ConfigParser mantiene `.sks`, clave GCM/PBKDF2-SHA256/1000/128/nonce12 y DES
histórico; la ruta exporta Properties XML. La rama abierta escribe
file.proteger=0, bloquearRoot=0, file.pedirLogin=0 y file.validade=0; contraseña
e ID de usuario no son la clave del sobre. No se han obtenido ni probado un
`.sks` exportado real123 o una importación física. No se registra escritor
Unlocked ni sufijo nuevo basándose solo en esquema o vectores sintéticos.

Continuar con descarga real del manifiesto/archivo desde un entorno con acceso
al origen, ejecutar speicers_verify.py sobre sus bytes y comparar el documento
entero antes de cambiar el broker. Para certificar Unlocked falta un `.sks`
real de este build y posterior importación Android. No fabricar perfiles desde
el catálogo como sustituto. APK, Java, cuerpos y JSON reales fuera de Git.
Sin fusión, despliegue, compilación APK, Actions manuales o novedades C11.

---

# Evidencia de Speicers Pro 104.1.17

Muestra autorizada de 2026-10-24, paquete `netfree.mx.store`, código 120.
APKS SHA-256: `5c1dfc245711dd5701234f5cee8f92d843d8be994afc27e588a2a4789b175d61`.
APK principal SHA-256: `c32d5166e3bbab1ac15045533056d33ed65e7db1a9707e887531212174ea2aa9`.
Las copias del APK, DEX, catálogos y resultados reales quedan fuera de Git.

Se leyó la guía de continuación del servidor y RESTORE.md desde el HEAD del
PR #99, `fd025ee972a87b325c16b45a97b81cca129f5c88`. No se encontraron AGENTS.md
en el checkout ni en los directorios superiores aplicables. Se conserva la
misma rama sin fusionar, publicar una aplicación ni desplegar la VPS.

## Ruta principal realmente consumida

`VTlK_TpMFHrWRIDm_k.REhg2Fdx8QoajncCp()` abre `libgojni.db` privado y, si no
existe, `assets/flags/config.png`. Llama a `fnmzfQzIneovrhihvdUDg.Tg_eafVAJ1Sem22`:
Base64, magic `WakkoDev`, salt de 8 bytes, tres MD5 concatenados sobre
previous + password + salt, clave AES-256 de 32 bytes e IV de 16, CBC/PKCS5.
La constante exterior procede de `LICENSE:NIGHT_MODE`.

`iNoFpMfh2FRo5T_.Y98zvjwgmg91QOUYBumL` y el lector de nombres de servidores
llaman a `uT53lBcoF7Rp.RMBXgIvtNwk7QLhh`: Base64 URL-safe, primeros 16 bytes
como IV, resto como AES-CBC, clave UTF-8 rellenada con ceros hasta 32 bytes
desde `LICENSE:SSH_UDP`, después rotación de letras Java equivalente a +23.
Se reproduce la operación sobre unidades UTF-16, incluidas letras no ASCII.
Vacíos se mantienen vacíos; un campo protegido no válido rechaza todo el
documento. No se sustituye por `ERROR` ni se devuelve un catálogo parcial.

24 claves de campos se identificaron desde recursos y sus consumidores. Se
mantienen las claves originales; `OtrasConfigs` es booleano aunque su nombre
esté ofuscado y no se trata como texto cifrado. XHTTP, BHTTP, KTUN, flags TLS,
PAM y datos extra se preservan sin aplicar ni cambiar sus controles.

`srybNp01tN5CcwA_cE(Context,VazEm_vUnosM)` contiene dos orígenes. La rama
servidores usa `new bHpxA6qJ_zrmfW(4).toString()` y el auxiliar
`hpNtUD1CNW0w7ETBbL.run` selecciona ese origen y ejecuta GET. Se confirmó su
cuerpo con las 163 instrucciones Dalvik, incluyendo selección del origen y
setRequestMethod. El origen de usuarios se identificó pero no se consulta.
No confundirlo con el catálogo público de SP-DECODE.

HTTP 200: 105132 bytes, versión 35 y 74 servidores. Asset principal: 106456
bytes, versión 36 y 75 servidores. La diferencia se conserva: no es un fallo
de truncado ni permiso para eliminar el servidor adicional del asset.

## Asset secundario

`yM8Q42J2adlylYz33pH`, caso 5, copia `config/config.json` a `Config.json` y usa
`REhg2Fdx8QoajncCp` para escribir customizaciones vacías. Se recuperó el cifrado
del asset secundario invirtiendo esa rutina: alfabeto de 16 glifos a nibbles,
Base64, AES-256-CBC con IV cero; SHA-256 de la representación hexadecimal UTF-8
en mayúsculas de la constante de `bHpxA6qJ_zrmfW(5).toString()`.

Documento secundario completo: versión 9, 32 servidores, campos interiores en
claro. Se valida y conserva como esquema separado. No se considera sustituto
de la ruta principal de 75 servidores, ni se le inventa una fuente remota.

## Exportación y otras funciones

`netfree.mx.tunnel.config.ConfigParser`: `FILE_EXTENSAO=sks`, métodos
`convertDataToFile`, `encodeInput`, `decodeInput` y `convertInputAndSave`.
`decodeInput` tiene una ruta GCM y una histórica DES con constantes iguales a
HTTP_FenixVPN; `SecurityConfig.Builder` usa PBKDF2-SHA256/1000/128, salt32 y
`CipherServiceImpl` confirma GCM/NoPadding/nonce12. Contraseña/HWID no alimentan
esa clave. No se ejecutó Android ni se aportó una exportación `.sks` real.

Manifest: esquema `speicerspro`, host `payment`, actividad PaymentReturnActivity;
no es una exportación cloud. No se identificó esquema propietario de perfiles
por texto o token. No se consultaron checkUser, pagos ni anuncios. Las rutinas
de integridad nativa y `sgdx55.bin` no intervienen en los lectores offline.

JADX 1.5.6, instalado con hashes fijados por decompile.py, finaliza con 21
errores generales. Se contrastaron los métodos de interés con Dalvik y con
JDK independiente; no se afirma una descompilación completa del APK. La primera
exploración usó JADX 1.5.3; la revisión final y recuperación usan el fijado 1.5.6.
