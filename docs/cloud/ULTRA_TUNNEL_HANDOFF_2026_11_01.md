# Ultra Tunnel: descarga de catálogo integrada — 2026-11-01

**Completada en código; despliegue y prueba en VPS pendientes.**
Cuenta Goku, rama `fix/http-jireh-current-method`, base
`6d9dc8c89e2f8248ea75776658947d86671ba0c4`.
El propietario seleccionó Ultra Tunnel, paquete `co.strongteam.ultra`.
No se retoman automáticamente las otras apps pendientes.

## Resultado real

La petición fija del original respondió **HTTP200, text/plain,1384477 bytes**.
Catálogo **Version5.18,47 Servers/917 Networks**.
Se autenticaron **5034 campos protegidos distintos**.
El **JSON entero**, incluidos desconocidos, duplicados de listas, vacíos,
Unicode, booleanos y metadatos, coincide con libsodium Argon2id y Java/JCA GCM.
Una descarga nueva por la CLI y el worker aislado producen el mismo documento.

No se usa el catálogo incluido para acreditar la descarga. Los datos reales,
binarios y resultados descifrados permanecen fuera de Git.

## Original y procedencia

Original disponible: **v1.0.8.8/build59**, ARM64, minSDK32/targetSDK36.
Google Play identifica la app de sando--k y actualización10-agosto-2026;
el distribuidor ofrece59/v1.0.8.8 y el binario confirma paquete, versión y build.
No se afirma descarga directa de Google Play ni comprobación independiente
de su firma mediante Play.

Fuente de bytes:
`https://d.apkpure.net/b/XAPK/co.strongteam.ultra?version=latest`.
La huella SHA1 del firmante coincide con la que publica el distribuidor:
`3927a6a0f89925edfa329c71c75359532362a34b`.
Signer SHA256:
`b8795cdd896d40eac94ded52601628b56166f6ec50536409ec77c22a754772f9`.

| Pieza | Bytes | SHA256 |
| --- | ---: | --- |
| XAPK ARM64 | 58547704 | `ef468443c9e1c17e3bf8d18f227b4c7c64462f05a4104ba3c9735dc5519e6109` |
| Base APK | 32381008 | `196ac85cd4bb713abf49985d8f4c82c2db7adf2a675677440f8234bf58fa8c9e` |
| libgojni.so ARM64 | 30750392 | `32840bca9b80405d90563c4e910433a4d36c8c83a93d4b0132eee35ae7537c87` |
| Catálogo remoto5.18 | 1384477 | `60d0638e9c1e7f84d4baaf6ce135e3b7c33a27c6e474f54229856b02863f5134` |
| JSON completo, sin newline final | 843755 | `bd7eba4c67a1c61cc7a539708d13df5529660c290cf10e25226387f2f83be740` |
| PNG original res/drawable/icon.png | 306646 | `d382fd15f5a0fa172031bd57227ba596ac9b96b6857efce2f63ecd3e6457c74c` |

Se conservaron privadamente `Ultra-Tunnel-v1.0.8.8-build59-arm64.xapk` y
`Ultra-Tunnel-remote-5.18.enc` para recuperación por nombre.
El icono es el PNG512x512 exacto del APK, sin redibujar ni recodificar;
no se presenta como una captura/render del icono adaptativo.

JADX1.5.6 terminó exit3 con177 errores generales. Se inspeccionaron las rutas
nombradas y la biblioteca Go; no se afirma descompilación total.

## Petición vigente y flujo

`ConfigUpdate$configUpdate$1.invokeSuspend -> Libv2ray.cu -> CU`.

| Parte | Receta confirmada en ARM64 |
| --- | --- |
| URL | https://strongteam.co/api/ultrasystem/ultrav3.txt |
| Método | GET |
| User-Agent | Ultra Tunnel |
| Cuerpo | Ninguno |
| Authorization/API key/cookies/sesión | No usados por esta ruta |
| Renovación | No hay un flujo de sesión previo para este actualizador |

CU0x1019500/1056 bytes construye NewRequestWithContext con GET y la URL fija,
añade únicamente User-Agent y abre el cuerpo con decrypt0x1015fe0/576 bytes.
DO0x1016970/944 bytes proporciona el descifrado interior.
`ultra_tunnel_source_check.py` comprueba hash exacto del SO, funciones,
instrucciones de CU, cadenas y coincidencia de las constantes existentes;
no ejecuta JNI ni la app.

Las constantes de formato ya estaban en `decoders/Python/ultra.py`.
Se reutiliza su perfil `ultratunnel` después de compararlo con el binario;
no se añaden secretos privados, tokens ficticios o variables vacías.
La autorización incluida del actualizador no se omite: no hay otra en CU.
Accept-Encoding:identity permite aplicar límites sobre los bytes recibidos.
TLS y hostname se verifican; CLI y broker rechazan redirecciones.

## Cifrado y conservación del documento

Sobre remoto: una letra ASCII insertada en índice3 del Base64. Tras retirarla,
salt16/nonce12/ciphertext/tag16. Argon2id v19,t3,m8192KiB,p1,key32,
AES256-GCM con AAD=salt. El asset usa el sobre EO/DO sin la letra y con
la clave secundaria; la selección depende del framing, no de ignorar tags
ni probar perfiles de otras apps.

Campos interiores: mismo Argon2id/GCM con la clave secundaria verificada.
Contextos: raíz, Servers y Networks, siguiendo getters/consumidores del original.
Se descifran los campos de configuración conocidos; Info, URI, metadatos
y campos desconocidos se conservan. Un sobre protegido con tag incorrecto
rechaza el catálogo entero; no se devuelve un resultado parcial o un alias.
Cache por documento, hasta8192 campos únicos, sin persistencia de credenciales.

La salida no agrega perfiles, no filtra protocolos y no transforma cadenas
JSON en otros tipos. No establece conexiones VPN ni genera cuentas.

## Integración

- Módulo `apps/Ultra_Tunnel` y CLI autónoma, entrada offline explícita o
  descarga fija. Bridge y allowlist del worker registran `ultra-tunnel`.
- Broker HTTPS fijo con DNS público fijado, límite8MiB, sin URL de cliente
  ni redirecciones. Control persistente C12 independiente.
- Ficha **Ultra Tunnel** con PNG original; **58 fichas**, fuente59 conservada
  para la entrega pendiente. Continúan9 fichas remote:null.
- Gateway exige proveedor/kind correctos, listas completas, nombres,
  Version no vacía y equivalencia de rawText/structuredJson.
- Android acepta fichas e identificadores dinámicos del catálogo. No se cambia
  el APK, versión Android ni el diseño. C0 sigue240 y C8 sigue255 formatos.
  Los lectores de archivos Ultra/Sandok y sus extensiones permanecen intactos.
- El presupuesto existente del worker de catálogos es120s. La decodificación
  directa real tardó61.48s; el worker aislado62.61s en este entorno. No se
  aumentan límites globales y no se promete la misma latencia en otro equipo.

## Validación y límites

- **9 Python aprobadas,0 omisiones**:8 Ultra y1 registro C8.
  Tres documentos sintéticos de JCA (plain/EO/remoto), todos los campos,
  tipos, tags exteriores/interiores alterados, límites, errores saneados,
  CLI desde/tmp y worker aislado.
- **97 Node aprobadas,0 omisiones**:7 Ultra y regresiones de catálogo,
  broker, versión, C12, MM, Enaa y ZiG.
- **Remoto real completo** igual a la referencia independiente
  libsodium/JCA,5034 campos,47/917.
- **CLI --download real**, ejecutada desde/tmp, realiza otra descarga y
  devuelve JSON entero igual. El newline del CLI no forma parte del hash
  del JSON sin newline de la tabla.
- **Worker aislado real**, sin red y con la respuesta remota guardada:
  rawText y structuredJson íntegros, isPartial:false.
- **7 comprobaciones de replay del gateway aprobadas** usando los bytes
  remotos reales y la respuesta del worker real. HTTP del proveedor,
  HTTP interno y Redis/sesión se modelan localmente: no es producción.
- Generador del catálogo de formatos aprobado. No se ejecutó toda la suite,
  un build web/Android ni instrumentación física.
- Un intento real con el transporte Node del broker terminó
  **REMOTE_NETWORK_DENIED**; la comprobación DNS del host devolvió
  **EAI_AGAIN** para strongteam.co. No alcanzó el origen. Se mantiene el
  transporte de producción, sin cambiarlo para eludir el proxy del entorno.
  La descarga Node directa y la ruta desplegada del VPS no están verificadas.

[Comandos y alcance de las pruebas](../../decoders/Python/apps/Ultra_Tunnel/TESTING.md).
No se afirma que9/97 pruebas equivalgan a una sesión VPN o importación Android.

## Despliegue posterior

No se fusionó main, desplegó, lanzó CI manual, compiló APK/AAB ni publicó avisos.
Al desplegar con autorización posterior, seguir el runbook VPS/HPKE,
preservar claves y switches y elevar la versión efectiva del catálogo por
encima de la ya servida. El fingerprint C12 detecta la nueva ficha; comprobar
su sincronización y el control Ultra sin reactivar proveedores deshabilitados.

Validar la descarga Node por la ruta autenticada del VPS y confirmar Version,
recuentos y JSON completo. El éxito Python y el replay no certifican ese paso.
UT Loop y FlexNet conservan sus pendientes documentados.
