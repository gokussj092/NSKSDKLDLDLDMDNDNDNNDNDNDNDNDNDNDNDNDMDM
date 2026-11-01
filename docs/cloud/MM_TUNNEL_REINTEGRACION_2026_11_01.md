# MM Tunnel: reintegración del catálogo remoto — 2026-11-01

**Completada en código; despliegue pendiente.** Esta entrega cierra únicamente
MM Tunnel. El propietario pidió resolver una aplicación y reportar antes de
continuar. Orden restante: **CREEB VPN, AM TUNNEL LITE VPN, UT Loop Pro VPN,
ProNeet VPN, EUT VPN, TunelGuard VPN**. No se investigaron ni activaron esas seis.

Cuenta **Goku**. Repositorio
`gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM`.
Rama `fix/http-jireh-current-method`, sobre
`64ea621350d0a0695b5203869de38a243c8ab57c` (ZiG). Al empezar, main permanecía en
`5a1c93a483619370ab0a155ed3d0ecd19ee8169c`; la rama no se había fusionado.
Se conserva la rama pendiente, sin mezclar un main anterior. No hay AGENTS.md
en el árbol del repositorio. Guía y documentación de reinvestigaciones leídas.

## Problema y corrección

El lector previo descifraba el asset, pero su descargador enviaba
**`type=xsandokUpdatex`**. Recuperar la URL y la constante sin comprobar el
nombre real del parámetro dejó incompleto el flujo remoto.

La versión vigente **v1.10.30.2/build47**, paquete `co.strongteam.marvsudp`,
confirma `ConfigUpdate$configUpdate$1 -> Libv2ray.cu -> CU` y:

| Parte | Receta del original |
| --- | --- |
| Fuente | `https://strongteam.co/api/mmtunnel/` |
| Método | POST |
| Formulario | **`hash=xsandokUpdatex`** |
| Content-Type | `application/x-www-form-urlencoded` |
| User-Agent | `Go-http-client/1.1`, predeterminado del cliente Go |
| Acceso adicional | No hay sesión, API key privada, Authorization, cookies, registro ni nonce en esta ruta |

La constante del formulario ya estaba versionada y se reutiliza para la
operación fija del actualizador. No es una huella que deba calcularse con datos
del dispositivo; tampoco se necesita un secreto privado adicional en el VPS.
No se implementó una suplantación de atestación ni se ejecutó el APK.

Tras corregir la clave del formulario, la petición real respondió HTTP200.
La CLI pública del módulo volvió a descargar y descifrar por su propia ruta,
fuera del checkout, con igualdad del JSON entero. El asset no suplió la descarga.

## Original y recuperación duradera

Google Play en vivo mostró v1.10.30.2. Se obtuvo el XAPK original disponible en
APKPure mediante `https://d.apkpure.net/b/XAPK/co.strongteam.marvsudp?version=latest`,
con User-Agent HTTP normal de navegador; el tipo APK devolvió403. No se resolvió
ningún challenge ni se afirma descarga autenticada desde Google Play.
Paquete/versión/build se verificaron en el APK. Variante **armeabi-v7a**,
minSDK32/targetSDK37. El certificado coincide con el fingerprint que documenta
el distribuidor; no se afirma una comprobación independiente del signer de Play.

| Pieza | Bytes | SHA256 |
| --- | ---: | --- |
| XAPK build47 | 54569520 | `8cf714a8545caa92a85bf956af8ab61a8edc3f385914533877d34ef29338b1e1` |
| `co.strongteam.marvsudp.apk` | 28530106 | `ef20dcf63aa6a011bc22d927a0f383a884e8924a9df1909ca555121e9e9d4d40` |
| `lib/armeabi-v7a/libgojni.so` | 28892484 | `b030c0f2b7684becfba0bad7e44b0873206359bb4017ac7e9eb549e377ab90c2` |
| Asset `assets/configfile.json` | 816912 | `ae4a7b72044b354826449700c031fc3da93dd94ae0834a083b3c828d5bb32880` |
| Respuesta remota2.46 | 822713 | `d36899110cd6976e8e43935fdd6a0e19952f8a3f12716f8a36fd7642fecc6241` |
| PNG original conservado | 109337 | `be2bb0a69da20838aaa46c388ab898a33b84cab59ccdad7413b76eac21b7b211` |

Signer SHA1 `b3d1c77b6cdb2f8b2c154c937de6b26669584d9a`;
SHA256 `4cfc4aae2984b26da41ab2ec71000edf1e8f5a73a738292fd452235a9e6456c3`.
El PNG `res/drawable/icon.png` mantiene exactamente el original ya publicado;
no se reemplazó, rediseñó ni recodificó la imagen.

Recuperar por sus identidades exactas, sin depender del scratch:

- `MM-Tunnel-v1.10.30.2-build47.xapk`:
  **`libfile_405ee8ff1188819197279172587d3448`**.
- `MM-Tunnel-remote-2.46.enc`:
  **`libfile_fd3cbd77480c81919a18504cb249c890`**.

Ambas escrituras finalizaron correctamente. El APKS anterior build45 también
existe como `MM Tunnel_v1.10.11.1.apks`,
`libfile_d7e8128fc3488191a0cdddc5b1ed5d8a`; no fue necesario descargarlo otra vez.
Los APK/SO, catálogos reales y JSON descifrados no se incorporan a Git.

## Evidencia del método

JADX1.5.6: exit3,78 errores generales; no se presenta una descompilación total.
LSParanoid recuperó7706 cadenas en500 fuentes y9738 entradas de inventario.
El inventario y los DEX recuperados son análisis privado.

Go ARM32: pclntab f1 en0x12fadb8, textStart0x2efa08,36934 funciones.

| Función | Dirección | Tamaño |
| --- | --- | ---: |
| Encrypt | `0xfd2878` | 1216 |
| decrypt | `0xfd2e0c` | 896 |
| EO | `0xfd3510` | 1092 |
| DO | `0xfd3b58` | 1116 |
| CU | `0xfd7154` | 1696 |

CU construye url.Values, asigna **hash** desde0x10d5b4/len4 y su valor fijo
desde0x118bef/len14, serializa con Values.Encode y crea el POST a la URL de
0x13af52/len35. Solo añade Content-Type, crea un cliente nuevo y abre la
respuesta con decrypt. El reproductor `mm_tunnel_source_check.py` comprueba
los hashes exactos y las instrucciones de las cargas PC-relativas ARM antes de
emitir la receta; no ejecuta código de la aplicación.

Se mantienen Argon2id v19,t3,m16384KiB,p1,key32 y AES256-GCM:
salt16,nonce12,tag16,AAD=salt. Exportación/remoto usa una clave de formato de32
bytes y una letra insertada en índice3 del Base64. EO/DO usa otra clave de21
bytes para asset/campos. Ambas constantes coinciden con las ya implementadas.

Los campos se descifran exclusivamente en sus contextos raíz/Servers/Networks.
Info se muestra directamente y URI es Boolean en el consumidor original;
no son una razón para intentar AES sobre metadatos desconocidos. Las listas,
tipos, placeholders, campos futuros y cadenas JSON se conservan íntegros.
Cada tag de un campo protegido debe autenticar o falla el documento completo.

## Resultado y pruebas

Remoto real: **Version2.46,38 Servers,557 Networks**,822713 bytes;
**3399 campos protegidos distintos**. JSON completo de500239 bytes.
La lectura directa completa tardó87.63s aquí; se mantiene el presupuesto
existente120s de catálogos. La latencia en otra máquina puede ser distinta.
Asset conservado:1.01,34/555,hash idéntico al previamente validado.

- **29 Python aprobadas,0 omisiones**:11 MM,1 registro,8 Enaa,9 ZiG.
- **129 Node aprobadas,0 omisiones**: MM y regresiones del broker, catálogo,
  C12, versión, contrato worker, formatos y ALFAISAL/IZPH/VIP/Enaa/ZiG.
- **7 documentos completos** contra libsodium Argon2id y Java/JCA AES-GCM:
  seis sintéticos y el remoto real;3411 campos por-documento en total,
  3399 del remoto. Worker aislado completo, sin parcialidad.
- CLI de descarga real sin argumento: otro POST correcto y JSON entero igual.
- Replay del gateway con el catálogo real validado:7 comprobaciones aprobadas,
  cifrado íntegro y JSON íntegro, sesión/cuota correctas. Transportes Node
  externo e interno simulados; no se afirma egress Node real ni VPS desplegado.
- Fuente fija, Content-Type, UA, POST y bytes exactos del formulario, límite de
  tamaño, DNS privado denegado, TLS y rechazo de redirects comprobados.
- C0 sigue240; C8 sigue255 y29 overrides. Generador de formatos aprobado.

Comandos reproducibles y alcance de mocks: [TESTING.md](../../decoders/Python/apps/MM_Tunnel/TESTING.md).

## Integración y próximo despliegue

El módulo/bridge/engine MM ya existía. Se corrigen descargador, metadatos .mmt y
campos; se añade el proveedor fijo POST, su etiqueta C12, conexión remote de la
ficha y validación íntegra en el gateway. Los switches de otros proveedores se
conservan. La documentación de pendientes pasa de10 a **9 fichas remote:null**;
se mueve MM al historial de resueltos en código.

Se mantienen fuente59 y57 fichas por la política del lote pendiente. Al
publicar, aumentar la versión efectiva por encima de la del VPS para refrescar
cachés, con el runbook VPS/HPKE, respaldo y verificación. No se necesita un APK
nuevo para este cambio Cloud. Verificar la descarga por la ruta real desplegada
y el switch MM; la comprobación local no acredita esa etapa.

No se fusionó main, desplegó, publicó, modificó diseño Android/panel ni compiló
APK/AAB. No se lanzaron workflows manualmente; commit con skip ci.
Siguen pendientes una exportación .mmt real y la importación en teléfono.
No se añade escritor ni se inventa un prefijo mmt://.
