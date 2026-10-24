# Aura Net VPN AuraNet_v9 (19) — análisis

## Identidad y evidencias

Paquete `civ.snipher.v2ray`, nombre Aura Net VPN. APKS de 46609558 bytes,
SHA-256 `36af163620fb203dde7ccd41a498d4582ad7f08ca1c01ea3e86e909348b336ad`.

| Componente | Bytes | SHA-256 |
|---|---|---|
| base.apk | 30851654 | `e691a444693c7a496fbc36e852c16c78ca87677de998d7d4a7730c7becd87ef2` |
| libgojni.so ARM64 | 32763248 | `75708706f815efdbe3fcd28a97799f33acba27b32309ce6239ba07cfbe09a8ab` |
| assets/configfile.json | 585016 | `8c268b58dbb59fc322c6cfc3e4f9a62284d1fd059bcd79dd860601f47a138a56` |
| res/drawable/icon.png | 126994 | `5f4f3a82d52822d84d04e9700b5b28ef084a319151431c7d91423ff3366701fe` |

El icono PNG es un recurso original Aura del APK y se copia sin redibujar ni
recomprimir. El launcher es adaptativo XML/WebP; no se presenta ese PNG como
un archivo de launcher si su ruta es `drawable/icon.png`.

JADX 1.5.6 fijado por checksum: DEX3 contiene la app y termina con 15 errores
generales; DEX1 con 43. Los métodos relevantes tienen cuerpos y se contrastan
con Dalvik exacto y Go. No se afirma descompilación total. No se ejecuta el APK,
JNI, arranque Android, comprobaciones de identidad ni funciones Go de red.

## Exportación, importación y secreto

`Lcom/v2ray/ang/adapter/NetworkAdapter;.u`: 149 instrucciones Dalvik.
Serializa NetworkList con Gson, pasa el JSON a `Libv2ray.encrypt`, escribe
en MediaStore y comparte `.aura`, MIME `application/x-aura`. El tercer
argumento selecciona la aplicación receptora; no es una contraseña.

`ConfigFileParser.onCreate`: 158 instrucciones. Límite de importación de la
app 2097152 bytes, lectura UTF-8, `Libv2ray.parseConfig`; alternativa
`JSONObject(Hometab.Companion.a(data))`, que llama a `Libv2ray.do_`.
`main.proxylibv2ray__ParseConfig` llama directamente a la función Go decrypt.
No se ve un parámetro de contraseña personal ni clave pública/privada.
El lector Cloud tiene su límite independiente de 8 MiB.

## Go y criptografía

`go_inspect.py` recupera 39794 funciones mediante pclntab y relocaciones.
Las funciones relevantes pertenecen a `github.com/2dust/AndroidLibXrayLite`:

| Función | Dirección | Bytes |
|---|---|---|
| Encrypt | `0x1a4a4c0` | 704 |
| decrypt | `0x1a4a820` | 544 |
| EO | `0x1a4ad10` | 608 |
| DO | `0x1a4b0f0` | 912 |
| CU | `0x1a4de80` | 1024 |

Ambos pares derivan **Argon2id v19**, t=3, m=`0x2000` (8192 KiB), p=1,
salida de 32 bytes. AES-256-GCM, salt 16, nonce 12, tag 16 y AAD=salt.
El binario es `salt || nonce || ciphertext || tag`, codificado Base64 estándar.

Encrypt/decrypt utilizan los 32 bytes en `0x3b35e5`; EO/DO utilizan otros
32 bytes en `0x3b3605`. Las constantes residen en `codec.py`. Encrypt inserta
una letra ASCII en el índice 3 del Base64 y decrypt la elimina. EO/DO no
tienen esa letra. Son claves distintas del perfil histórico `auranetvpn`
de `ultra.py`, que no se modifica. La autenticación siempre incluye el salt.

El asset usa EO exterior. Los campos internos emplean EO sin marcador;
el remoto y los perfiles exportados emplean Encrypt. El envoltorio Java
puede conservar texto plano cuando una llamada nativa falla; se admite
texto plano en campos, pero una envoltura cifrada reconocible con tag inválido
se rechaza. No se reintenta el lector permisivo después de autenticar un
documento moderno, ni se omiten campos rotos.

DO contiene contadores temporales y flags de estado/identidad. El lector
reconstruye el cifrado con las constantes de formato; no ejecuta ni altera
esos controles en la aplicación original. No hay requisito criptográfico de
root, reloj, identidad Android, cuenta o contraseña elegida por el usuario.

## Actualizador real

CU construye GET a la cadena literal de 46 bytes en `0x3cab03`:

```
https://strongteam.co/api/kidvpn/v4/aurav1.txt
```

Fija `User-Agent` desde `0x38f465` al valor `Aura Net VPN` de `0x391a47`.
La petición no incluye appcode, formulario ni token. CU aplica decrypt y lee
Version; `ConfigUpdate$configUpdate$1` recoge gfc y guarda el catálogo completo.
No se usa la URL histórica inerte `api/auranet/v1/` del inventario genérico.

El GET exacto con `Accept-Encoding: identity` respondió 200, 646873 bytes,
SHA-256 `329c4d71f865879e3b37f56041780849a653a734122b5316e1a927aa2328c1f5`.
El contenido autenticado exterior tiene 485110 bytes UTF-8, Version 2.18,
14 servidores / 685 redes y 424 campos cifrados distintos. El asset abre
438716 bytes UTF-8, Version 1.01, 4 / 663 y 40 campos distintos.
Las catorce secciones de ambos documentos se conservan completas. La
referencia recorre todos los strings con forma de envoltura, independientemente
de la lista de campos del lector, y confirma que no faltan campos cifrados.

El broker usa solo HTTPS literal, resolución a IPv4 pública fijada a TLS,
límites y reintentos transitorios existentes. Rechaza redirecciones y orígenes
proporcionados por el cliente. CLI: GET fijo, timeout 25 s, 8 MiB y ninguna
redirección. Los workers son offline.

## Texto, catálogo e integración

No se identificó `aura://`/`auranet://` ni un cloud de perfiles por token.
Manifest registra archivos content `.aura` y enlaces estándar `v2rayng` de
instalación/suscripción. El texto que acompaña al archivo exportado es
promocional. No se añade un protocolo propio por inferencia.

`.aura` ya está en C0: se añade override C8 y delegación del bot; se conserva
la ruta histórica con ambos modos AAD. C0=240, C8=252, 23 overrides. Ficha
pública y control persistente, mínimo 43 / 44 fichas. El flag offline
preexistente corresponde al lector histórico Android; no se edita su código.
Los perfiles sintéticos no equivalen a una exportación real del build 19.

Rama del PR #99 sobre `a76add0`. Se conservan `aura_net_verify.py`, la
referencia libsodium/JDK, fixtures sintéticos y comandos en RESTORE.md.
No se incluyen SO/APK/DEX, catálogos, credenciales ni inventarios de strings
reales en Git. Sin fusión, despliegue, APK nueva o novedades automáticas.
