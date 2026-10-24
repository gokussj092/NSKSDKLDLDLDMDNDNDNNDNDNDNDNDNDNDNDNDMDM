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
