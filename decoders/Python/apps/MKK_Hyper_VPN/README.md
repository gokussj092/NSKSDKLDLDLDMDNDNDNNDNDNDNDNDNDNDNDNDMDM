# MKK Hyper VPN — 2.9.2

Paquete analizado: `com.hypervpn.mmk`, versión **2.9.2**, código 9.
Aplicación Flutter/Dart 3.10.1 para ARM64. Esta carpeta reúne sus lectores,
el icono original y la documentación. Ambos scripts son **independientes**,
requieren **Python 3.10+ y PyCryptodome** y no necesitan el APK al ejecutarse.

| Archivo | Función |
| --- | --- |
| `MKK_Hyper_VPN.py` | Catálogos AES-GCM/JSON, índices de suscripciones y descarga de sus fuentes. |
| `MKK_Hyper_VPN_textos.py` | Claves `mkk://` AES-CBC y URI VPN, pegadas o guardadas en un archivo de texto. Sin red. |
| `MKK_Hyper_VPN.png` | Icono original de inicio, PNG de 192 × 192 píxeles. |

**No se identificó una extensión propia de archivos de configuración**
ni un flujo de importación/exportación de esos archivos en esta versión.
El diálogo `CustomKeyDialog` importa texto `mkk://` del portapapeles.
El segundo script se llama `_textos.py` porque reproduce ese formato;
abrir un `.txt` es una facilidad del lector, no una extensión nueva de la app.

## Uso

Instalar la dependencia:

```bash
python -m pip install pycryptodome
```

Desde esta carpeta, descargar el catálogo principal, descifrarlo e imprimir
el JSON completo o guardarlo:

```bash
python MKK_Hyper_VPN.py --url
python MKK_Hyper_VPN.py --url -o catalogo.json
python MKK_Hyper_VPN.py respuesta_guardada.json -o catalogo.json
```

Consultar el índice de suscripciones y descargar las configuraciones de
sus URL:

```bash
python MKK_Hyper_VPN.py --url --source subscriptions -o indice.json
python MKK_Hyper_VPN.py --url --source subscriptions --expand -o suscripciones.json
```

`--expand` exige que todas las fuentes se recuperen correctamente. Para
obtener lo disponible con un informe explícito de las fuentes fallidas:

```bash
python MKK_Hyper_VPN.py --url --source subscriptions --expand --allow-partial -o informe.json
```

El informe contiene `catalog` con todo el índice original, `complete` y
`sources` en el mismo orden. Cada resultado lleva `index`, `status` y
`data` o un código `error`. El índice permite relacionarlo con su URL y
metadatos. No se deduplican perfiles ni se descartan entradas por `status`,
`vip` o nombre; tampoco se ocultan los errores. `--allow-partial` solo
tiene efecto junto a `--expand`.

Leer una clave individual:

```bash
python MKK_Hyper_VPN_textos.py --text 'mkk://BASE64_REAL'
python MKK_Hyper_VPN_textos.py clave_guardada.txt -o perfil.json
```

Reemplazar el marcador por la clave real. El lector también reconoce los
cinco protocolos claros que acepta `MkkKeyHelper.resolve`: `vless://`,
`vmess://`, `trojan://`, `ss://` y `socks://`.

## Fuentes del catálogo

| `--source` | URL identificada en la app | Resultado observado |
| --- | --- | --- |
| `servers` (predeterminada) | `https://f005.backblazeb2.com/file/mkkhyper/api_server.json` | Sobre GCM, versión 97 y 12 servidores. |
| `subscriptions` | `https://f005.backblazeb2.com/file/mkkhyper/subscriptions.json` | Índice JSON de diez suscripciones. |
| `static` | `https://flashvpn.sgp1.digitaloceanspaces.com/static.json` | HTTP 404 durante la comprobación. |
| `legacy-subscriptions` | `https://raw.githubusercontent.com/Tunzen665/flash-vpn/refs/heads/main/sub.json` | HTTP 404 durante la comprobación. |

Ejemplos para seleccionar otra fuente original o una ubicación explícita:

```bash
python MKK_Hyper_VPN.py --url --source static
python MKK_Hyper_VPN.py --url 'https://ejemplo.invalid/catalogo.json'
```

El dominio `.invalid` es un ejemplo. La app incluye además el espejo S3
`https://mkkhyper.s3.us-east-005.backblazeb2.com/subscriptions.json`;
se comprobó su índice completo. El respaldo estático
`https://blaze-vpn.sgp1.digitaloceanspaces.com/sv.json` devolvió 404.
El script usa la fuente seleccionada y no sustituye errores por cachés ni
consultas a otro catálogo.

`--expand` descarga las URL incluidas en el índice, como el flujo
`SubscriptionApiService.fetchSubscriptionServers`. Conserva el texto
recuperado y sus URI, sin ejecutar la sustitución aleatoria de proxy que
hace Android ni generar configuraciones Xray de ejecución. Los ficheros
GeoIP/GeoSite, notificaciones, anuncios y contadores no son catálogos VPN.

## Formato AES-GCM del catálogo

La configuración de plataforma de `MainActivity` entrega seis cadenas por
el canal `com.hypervpn.mmk/x`, método `g`. `SecureConfig.encServerUrl`
selecciona el campo `0` y `encPayloadSecret` el campo `5`.
`UrlEncryption.decrypt` aplica Base64 y XOR repetido con
`invisiVpnSecure2024`; es ofuscación de constantes del cliente.

`GitHubService._ensureInit` obtiene la URL y el secreto del formato.
`ServerDataDecryptor._deriveKey` deriva **SHA-256 de los bytes UTF-8 de ese
secreto**, produciendo una clave AES de 32 bytes. El lector conserva las
constantes compartidas necesarias; no necesita identificadores de usuario
ni tokens de cuenta para consultar el catálogo principal.

El contenedor JSON tiene:

- `nonce`: Base64 de 12 bytes.
- `cipher_text`: Base64 del cifrado AES-256-GCM.
- `mac`: Base64 del tag de 16 bytes.

Si `mac` está ausente o es `null`, la implementación del APK toma los
últimos 16 bytes de `cipher_text` como tag. El lector reproduce ambas
variantes. No utiliza AAD. **Se verifica el tag antes de analizar o mostrar
el contenido**; un fallo de autenticación no se convierte en JSON claro,
una lista vacía ni un resultado parcial.

Se preserva el documento claro completo: `version`, `servers`, claves
`key`, flags `vip`, campos desconocidos y sus tipos. También se admiten los
catálogos JSON legados con listas `servers`/`static_users`, arreglos de
servidores, índices `subscriptions` y mapas antiguos de nombre a URL HTTPS.
Los cuerpos de suscripción pueden ser líneas URI claras o Base64 de su
texto UTF-8; se devuelven `raw_text` y `profiles`, conservando duplicados.
No se hace recuperación heurística de JSON roto.

## Formato del texto `mkk://`

`MkkKeyHelper.decrypt` retira el prefijo, decodifica Base64 y separa los
primeros **16 bytes como IV**. El resto es AES-256-CBC con padding PKCS7.
La clave es el UTF-8 de `MKKHyperVPN_2025_SecureKey_v1.0!`, truncado o
completado con ceros hasta **32 bytes**. En esta versión el literal ya
ocupa exactamente 32 bytes. Los enteros de los argumentos obligatorios de `take` y `length=`
se pasan sin etiquetar en el AOT; se verificó ese detalle en las funciones
llamadas para evitar interpretar 32 como 16.

El resultado es una URI VPN UTF-8, **no un objeto JSON cifrado**. El lector
devuelve `protocol` y la `uri` exacta. Para VMess añade `config` con todo
su JSON; para los demás protocolos añade `details` con autoridad, ruta,
nombre y pares de consulta ordenados. Conserva parámetros repetidos y
vacíos, Unicode, IPv6, cadenas anidadas y CRLF. No traduce esos datos a otra
configuración de ejecución.

El formato CBC no incluye MAC ni firma y no usa una contraseña individual
de usuario. El padding y la estructura URI comprueban el formato, sin
constituir autenticación criptográfica.

## Evidencia y límites de validación

Comprobación del **18 de octubre de 2026, 23:41 UTC**: el catálogo principal
respondió HTTP 200 con 4.850 bytes de sobre cifrado; se autenticaron y
recuperaron los **3.578 bytes claros de la versión 97**, con 12 servidores
y todos sus campos. La CLI `--url` produjo el mismo objeto completo.
OpenJDK/JCE verificó GCM de forma independiente y coincidió byte por byte.

SHA-256 del JSON claro:
`de133de50070a123869959ee17cf9f4365d2fbf9ff5a7e5adadd8ab5b1af06e7`.

El índice de suscripciones tiene diez entradas. La descarga ampliada real
recuperó nueve fuentes con un perfil cada una y dejó una fuente fallida
indicada en el informe; al volver a consultar esta última respondió HTTP 503.
Por tanto, **no se afirma haber recuperado completas
las diez fuentes**, ni que los perfiles sean servidores distintos entre sí
o respecto al catálogo principal. No se probaron conexiones VPN.

No se adjuntó una clave `mkk://` real. Ese lector se validó con cinco
vectores independientes JCE, uno por protocolo. Los catálogos y claves
de pruebas son sintéticos y no contienen datos reales de servidores.

Desde la raíz del repositorio:

```bash
java tests/golden/MKKHyperVectorGenerator.java > /tmp/mkk_hyper_vectors.json
python -m unittest tests.test_mkk_hyper
```

Las 27 pruebas cubren GCM separado/adjunto, manipulación de nonce/cifrado/tag,
CBC, Unicode/CRLF, campos futuros, mil servidores, índices y expansión
completa/parcial, límites, HTTPS, icono y ejecución autónoma de ambos scripts.
Las pruebas automatizadas de red usan mocks.

Referencias del AOT de esta muestra: `MkkKeyHelper.decrypt` en `0x4fbd54`,
`_encrypter` en `0x4fc1e4`, `_aesKey` en `0x4fc268`,
`ServerDataDecryptor._decryptString` en `0x40eb78`, `_deriveKey` en
`0x4117fc`, `GitHubService._ensureInit` en `0x3f9424` y
`SubscriptionApiService.fetchSubscriptions` en `0x4efcc0`.
Se analizaron los DEX y el código AOT de `libapp.so` usando JADX y
[Blutter](https://github.com/worawit/blutter).

## Procedencia y contrato

- ZIP: `9d270b84ec570ca193e17829fe372d003c871417115882de2583899d73192b54`.
- APKS: `3074603567db970a2a5ae8132455aee2763d26a480182aa904e6089d4f688d8a`.
- APK base: `e45c339a7d713ea2c7b4121eb1867afda7f2ac2647da8b4679541e69474dc326`.
- Split ARM64: `eaaf53390c5d7f1797f43f3c6de5b0dc975ef023bb3fd86dd2b60943eb2e8ef3`.
- Icono: `base.apk/res/mipmap-xxxhdpi-v4/ic_launcher.png`, copiado sin recodificar.
- SHA-256 del PNG: `ea975a368608e49800eea2877c9966a75b9cc72e0b0d71e3b27e3b55eeb312e6`.

`decode(bytes_o_texto)` y `run(...) -> str | None` son offline.
`fetch_catalog` y `expand_subscriptions` son operaciones de red explícitas.
La CLI devuelve JSON completo a stdout o a `-o`, y errores JSON a stderr:
0 al completar, 1 por formato/descifrado/red y 2 por argumentos/archivos.
Con `--allow-partial`, el éxito de la operación indica que se escribió el
informe; `complete` determina si todas las fuentes se recuperaron.

Límites: 32 MiB por entrada/respuesta, 128 fuentes por expansión, 64 MiB
combinados de respuestas ampliadas, cuatro descargas concurrentes,
profundidad JSON 64 y un millón de nodos contando claves. Se rechazan
claves duplicadas, números no finitos y Unicode inválido. HTTPS obligatorio,
sin credenciales en la URL, hasta cinco redirecciones HTTPS y timeout de
20 segundos por operación de socket, sin reintentos automáticos.
Se valida antes de escribir; un error de formato conserva la salida
anterior. Pueden producirse errores del sistema de archivos al escribir.

No se versionan APK, respuestas reales, URI de servidores ni tokens de
cuentas. No se modifica Android ni el registro del bot.
