# Speicers`Turbo VPN 217.4.4 / build 217

## Identidad y procedencia

Integración Cloud solicitada por el propietario para `netfree.mx.anuncios` en
`feat/nuevas-integraciones`, PR #110. Sin Android, build, merge ni deploy.
La página viva APKPure ofrecía 217.4.4/217 aunque el índice mostraba 216.
Se analizó la variante ARM64, sin instalar/ejecutar la APK.

XAPK 46868973 bytes: SHA256
`9a8e62ff418210ddccb2688fc62e1086a9d73cd8d76faa6b9cc7f4259984e911`.
Base 23014068 bytes: SHA256
`13f9039e5c0df357d6bd8ea3e5a74cdf27201a505ad30106a204cfc759a85ccb`.
Certificado SHA1 `0d830fbfc97ac7d73b9ef865ddfb235870a526ad`, coincidente
con el mirror y la constante esperada de la APK. Esto no certifica el binario
Play más reciente ni sustituye apksigner. MANIFEST conserva DEX, tamaños y hashes.

## Descubrimiento, hipótesis y contraste

`prepare.py` invoca el inspector compartido y extrae DEX/assets y bibliotecas
ARM64 pequeñas como datos. JADX 1.5.6 produjo código parcial para classes.dex
(exit3, 18 errores) y terminó correctamente para classes2.dex (exit0).

`recover_strings.py` interpreta hex y XOR de cada método. La primera revisión
era específica a registros r7/r8; otra no distinguía nombres duplicados de
clases anidadas. La versión vigente omite esos nombres ambiguos: 667 literales,
40 archivos, dos nombres omitidos. No implica que todo el decompilado sea fiable.
`literal_arrays.py` recupera 111 cadenas mediante operaciones enteras Java,
casts y arrays, sin eval, JNI ni ejecución de clases. Las rutas y constantes
usadas se contrastan separadamente en constructores, recursos y JCA.

`t5p215r1.zs6nx3fss8` fija dos URLs en su constructor. `z5geu5j6js` contiene
la contraseña exterior. `ztgudtegvzms` lee LICENSE:NIGHT_MODE y carga incluidos
`flags/config.png` y `flags/usr.png`. La contraseña incluida y la remota coinciden.
`assets/configg/confiiiig.json` es auxiliar: no se registró como fuente activa.

El decoder exterior `t5p215r1.zsqvvm2s8` contiene MD5/CBC; el interior
`t5p215r1.z6u859m7p8hjersgdkj` y activities.zhxk3yses.zyj7fdurgqmw3th contienen
CBC/ROT. `recover_resources.py` resuelve ID 2131820545 a res/raw/pdnsd_config
y lee KEY_CONFIG. Tres campos de identidad se observan literalmente en el
helper servers.zhxk3yses; los demás están en recursos. La hipótesis inicial
«todos están en una sola clase R» falló y se corrigió, con revisión conservada.

Se inspeccionaron estáticamente JNI_OnLoad/12 registros de libcrypto y símbolos
de las bibliotecas pequeñas de guards/HCR. No se ejecutaron guards, librerías,
DEX oculto, lógica de cuenta/licencia ni conexiones VPN: no fueron necesarios
para el formato confirmado. No se instaló/utilizó Unicorn.

## Descarga real y formato confirmado

| Fuente fija GET | HTTP / tipo | Bytes | Versión / filas |
| --- | --- | --- | --- |
| raw GitHub apksdemons/apks2/refs/heads/main/speicers/spei_servrs | 200 / text/plain UTF-8 | 407832 | 17 / 266 Servers |
| raw GitHub apksdemons/apks2/refs/heads/main/speicers/spei_users | 200 / text/plain UTF-8 | 1984 | 2 / 2 Usuarios |

HttpURLConnection no añade un User-Agent específico en el código de la app.
Se usa un perfil analítico Dalvik/2.1.0 (Linux; U; Android 14), explícitamente
sin afirmar que sea una captura física/atestada. CLI y broker usan el mismo
perfil; Accept-Encoding identity y TLS verificado, sin autorización/cookies.
Los GET operativos se repitieron, también tras recuperar el entorno, con los
mismos hashes. El incluido de servidores coincide con el remoto; el incluido
de usuarios es versión 1 y otro hash, nunca sustituye la versión remota 2.

Exterior: Base64 estándar → WakkoDev (8 bytes) + salt (8) + AES256-CBC/PKCS7.
Material de 48 bytes: MD5(previous || password UTF-8 || salt) repetido, clave32
y IV16. No es PBKDF2 ni Salted__. Interior: Base64 URL-safe Android sin padding
obligatorio → IV16 + AES256-CBC/PKCS7; KEY_CONFIG UTF-8 truncada/rellenada con
ceros a32. Texto → ROT21 con Character.isLetter/isUpperCase Java, por UTF16;
equivale a invertir la cifra5 con 26−5.

Se reutilizan primitivas y 27 nombres de servidor/6 de usuario de HTTP_FenixVPN,
sin modificar ese módulo ni utilizar sus claves. El censo rechaza cadenas
opacas no revisadas y conserva tipos, metadatos desconocidos y todas las filas.
Se abren 2649 campos de servidor y 12 de usuario remotos: JSON completo igual
a Java/JCA independiente, Python, CLI archivo/stdin y worker aislado.

## Resultado, recuperación y límites

Proveedor speicers-turbo-vpn, bundle obligatorio de ambas fuentes, broker,
gateway, worker, control e icono original res/drawable/icons.png conectados.
PNG512×512/48036 bytes, sin recomprimir; piso68/64 fichas y 256 formatos.
Constantes inline en el backend por petición del propietario, sin .env nuevo.
Si una fuente falla no se presenta un éxito parcial ni se usa un incluido viejo.

10 Python y 154 Node pasan, repetidos tras reconstruir el entorno. Dos aserciones
históricas esperaban 63 fichas y se corrigieron a64 en la primera sesión. Sus
logs originales se perdieron antes de Git: generated/checks-initial.json los
identifica como evidencia del historial, no como un archivo recuperado íntegro.
RESTORE explica la reconstrucción textual y sus límites. Los scripts actuales
sí se ejecutaron y sus hashes/resultados están conservados.

CBC no autentica los datos: padding/esquema/paridad no son un tag o firma.
Node directo aquí: REMOTE_NETWORK_DENIED; replay real de dos cuerpos y worker
correcto con HTTP/DNS expresamente simulados. VPS, revisión humana y rollout
pendientes. No se certifican archivos/texto/exportador ni conexión VPN.
