# Evidencia MTM Tunnel Lite

Analizado el 2026-10-25: `com.mtmtunnel.lite`, versionName `MTM`, build 40.
No se incorpora el APK, DEX, bibliotecas nativas ni plaintext real a Git.

| Entrada | Bytes | SHA256 |
|---|---:|---|
| APKS original | 28372392 | `9e0ff14de7a3ec2d2a3db49a803ab0b6c04051dfeea7b88c1460789b6f0ae55a` |
| base.apk | 15415387 | `87ac31c4f7a3dc982cbdfeb762f4874f341733cbcaf2f6144b544b705ce1b82e` |
| classes.dex | 7984028 | `05b4b73fde9c9867f46b2a540c05f80a5cf41a9af4f3a193c74068a0bbba18fd` |
| classes2.dex | 3264760 | `f8dd0043860a18c8ee442a3de443295b5b77c745661c3d0de6d38a087551a5c3` |
| assets/sept.json | 575384 | `feae1f2c44ba1c0580b67ec7f6111431bb4e34750de25cd66c123a7bfca1ce57` |
| res/drawable/ic_app_icon.png | 96510 | `b0e76f47ec044182148e2e1c95e211acc8fdc4c5ff961554e70164e1490a03d5` |
| Respuesta updater HTTP 200 | 361084 | `68d9887d10fa474c6d9c977773adeaa86a1503783686688ce4e6866bfa838d93` |

PNG original 512×512, copiado sin recomprimir. JADX 1.5.6 devolvió salida
parcial con 22 errores en DEX1 y 13 en DEX2; no se afirma decompilación total.
LSParanoid: `Deobfuscator$MTMTunnelLite$app` está en DEX2; 1166 constantes
literales / 42 archivos de DEX2 y 67 / 10 de DEX1, inventario 1487 strings.
Para DEX1 se debe indicar `--call-class Deobfuscator.MTMTunnelLite.app`.
Los argumentos pasados mediante variables long no se sustituyen automáticamente.

## Cifrado y datos completos

DEX2 `Sj.a` contiene `Princie!`; `aQ.a` llama `Sj.c(str,Sj.a)`.
`Sj.b/d` son XXTEA modificado, delta -1638454863 (`0x9E5729B1`), palabras
little endian, clave UTF-8 rellenada con ceros hasta 16 bytes, palabra final
de longitud y Base64 estándar exterior. Coincide con el motor HX ya existente;
se reutiliza con clave explícita, sin duplicarlo ni mutar sus constantes.
El contenedor no tiene MAC: longitud/esquema válidos no prueban autenticidad.

`prince.open.vpn.activities.a.D()` lee `sept.json` privado o asset, descifra
con `aQ.a` y construye JSONObject. Raíz observada: `Version`, `Changelogs`,
`Username`, `Password`, `Payloads`, `Free_servers`, `Premium_servers`,
`Vip_servers`, `Private_servers`. Se preservan exactamente, también campos
desconocidos, orden de arrays, tipos y Unicode. El render solo indenta JSON.
No se ordenan ni combinan las dos versiones.

`OpenVPNClient` consume `server_host`, `username`, `password`, puertos,
`payload`, `host`, `sausage`, etc. directamente tras abrir el catálogo;
no se identificó otra capa criptográfica en esos consumidores. `C0573zB.a`
lee Username/Password de D() después de descifrar: no son la clave XXTEA.
No se necesita contraseña de usuario ni identificador de dispositivo.

| Catálogo real | Versión | Free_servers | Payloads | Bytes plaintext |
|---|---|---:|---:|---:|
| Incluido | 35.55 | 29 | 471 | 431531 |
| Actualizador | 37.63 | 27 | 479 | 270806 |

Las otras tres listas de servidores están vacías en ambos. Los dos plaintext
completos coinciden byte por byte con Java independiente, y su JSON completo
coincide con el worker de catálogo y de archivos.

## Online y rutas originales

`OpenVPNClient.S()` construye el GET fijo:
`https://xtmtunnel.xyz/updater/527543543860c45bf4238f2a1b56c3`.
`OL` (DEX1) no añade cabeceras propias. Se comprobó HTTP 200 con agente mínimo
`Dalvik/2.1.0`, sin redirects ni credenciales. El consumidor real está en
`RunnableC0007Ad.run`, rama de entrega OL: quita espacios/LF, llama aQ.a,
lee Version y guarda el ciphertext en `sept.json` si hay actualización.

Advertencia para reproducir el análisis: JADX compilando DEX por separado
renombra clases por colisiones de mayúsculas; los `vB/wB` referidos por OL
no se deben confundir con los callbacks de consentimiento del mismo nombre
en DEX2. El flujo se contrastó con descriptores DEX y consumidor, no solo
con nombres de archivo Java.

No se identificó importación individual por referencia/clave, esquema MTM
propio o clipboard de perfil. Firebase/Recaptcha genéricos no demuestran una
función de cloud import. InjectorService arma una URL de conexión con
username/password/device_id/device_model; no se consulta como importador.
`vmess://` y `.ovpn` son formatos comunes preexistentes, sin nuevo registro.

## Archivos de actualización

`OpenVPNClient.onRequestPermissionsResult(99)` abre el selector con callback
`hH(this,15)`. DEX1 `ViewOnClickListenerC0685lm.onClick` acepta `.json` o
`.v2`, lee el archivo y llama exactamente `aQ.a(a.L(stream))`.
Esto prueba el mismo cifrado del catálogo, no un formato nuevo de perfil.
Hay una anomalía original: el selector escribe **plaintext en Servers.js**,
mientras D() sigue leyendo **ciphertext de sept.json**; no se afirma que
el selector refresque correctamente el estado del APK. El lector SP-DECODE
extrae el documento completo sin reproducir esa escritura.

`.v2` ya pertenece a e-V2Ray. El overlay C8/bot conserva ese lector al fallar
la apertura XXTEA; si la apertura funciona pero el catálogo es inválido, falla
sin fallback. C0 240 y Android nativo 239 no se regeneran con este overlay.
No se captura el sufijo global `.json`; ese caso queda explícito en la CLI.
No se añadió detección genérica de Base64 como texto de perfiles.

Sin muestras `.v2` independientes del usuario ni prueba física de móvil.
Las respuestas reales son catálogo asset/remoto; las pruebas de export/file
adicionales usan ciphertext sintético de Java y se describen como tales.
