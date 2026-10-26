# Análisis de Tx Tunnel — 2026-10-24

Continuación en `feat/mm-tunnel-1-10-11-1-decoders`, PR #99, partiendo del HEAD
remoto **f0918213d1854c508c7566ade5ace98c125c5bf5**. Se conserva el trabajo de MM.
Se consultaron las guías Android y de investigación nativa de
[morluto/rea](https://github.com/morluto/rea), en particular la selección exacta
de métodos, la distinción entre declaraciones nativas y cuerpos disponibles,
y la vinculación de conclusiones a los binarios analizados. No se instaló REA;
se usaron las herramientas verificadas ya conservadas en este repositorio.

Referencias consultadas: [Android](https://github.com/morluto/rea/blob/main/docs/android-analysis.md)
y [native investigation](https://github.com/morluto/rea/blob/main/docs/native-investigation.md).
No se copió código de REA ni se ejecutaron sus instrucciones de instalación.

## Identidad

Nombre **Tx Tunnel**, paquete **co.strongteam.ospro**, versionName **Tx v2.17**,
versionCode **70**. SHA-256 del APKS:
`4a07ad75060967ce8fe8bdf0012e961943cb2bd1f3ddc1992ffd0e70165d9f8d`.

| Componente | SHA-256 |
|---|---|
| base.apk, 28308691 bytes | `11e98058aec2d12dcdcdef873d17db6c906de0befff675764dc934d5337e7711` |
| libgojni.so ARM64, 30715288 bytes | `f96d542dccf5d5b522a2b58bf930ed8cf89deb1b15eeee458bd8d689f03461be` |
| assets/configfile.json, 141344 bytes | `6e79574aac23a770d1e9e9a989d0b6943e8227218bee71608da8dcc684a1f03c` |
| res/drawable/icon.png, 312819 bytes | `cc0507ce55fb41623379091f70732a932fb5df7c2f1b1c6e7875b1448f887772` |

El DEX de aplicación es **classes3.dex**. JADX 1.5.6 termina con código 3,
7 errores generales en DEX3 y 41 en DEX1; no se presenta el APK como totalmente
descompilado. Las rutas importantes tienen cuerpos y se confirman mediante
Dalvik y desensamblado Go. No se encontró LSParanoid en esas rutas.

## Exportación, importación y contraseña

- `NetworkAdapter.u`: **149 instrucciones Dalvik**. Gson de un `NetworkList`,
  llamada a `Libv2ray.eo`, escritura mediante MediaStore en Descargas y adjunto
  `.tx`, MIME `application/x-tx`. No recibe contraseña del usuario.
- `ConfigFileParser.onCreate`: lee archivo, `Hometab.Companion.a`, JSONObject,
  `Name` y `TunnelType`. Sin diálogo ni parámetro de contraseña en esta ruta.
- `Hometab$Companion$decUtil$1`: llama `Libv2ray.doo`; el wrapper devuelve la
  entrada si falla la llamada. Las restricciones de ejecución de la app no
  constituyen un secreto para el cifrado del documento.
- `HomeFragment` y `ServerStatusVIew` leen `SIDICONFIG` o el asset, pasan por
  DOO y usan los modelos `ConfigData`, `ServerList` y `NetworkList`.

La ELF contiene **36571 funciones Go**. Funciones del paquete
`github.com/2dust/AndroidLibXrayLite`:

| Función | Dirección | Bytes |
|---|---|---:|
| EO | `0x1012e70` | 672 |
| DOO | `0x1013290` | 960 |

En ambas funciones se construyen 17 bytes de secreto desde **0x34c0aa** y un
store de ocho bytes solapado en +9. Coincide con
`ultra.ULTRA_CONFIGS['txtunnel']['password']`, de modo que no se duplican claves
ni se modifica su perfil histórico. Argon2id (modo 2), t=3, m=0x4000, p=1,
salida 32 bytes; AES-GCM, salt 16, nonce 12, tag 16 y AAD=salt. No hay letra
insertada, doble clave de MM, clave pública privada ni password personalizado.
DOO también contiene control de llamadas por tiempo y comprobaciones de estado
de la app; el lector independiente reconstruye el cifrado, no arranca esa ELF,
no altera sus flags y no usa identidad Android en runtime.

## Actualizador real

`Hometab$onResume$1$1` construye GET
`https://strongteam.co/api/txtunnel/v1/?appcode=` más `rk1.g(context)`.
El descriptor Dalvik exacto de esa clase auxiliar es **Lrk1;**, no el paquete
artificial `defpackage` que muestra JADX. El método obtiene sourceDir.length,
divide por 1048576, formatea Locale.US `%.2f`, y convierte a Double.
Este base.apk produce **27.0**; no se prueban otros tamaños.

`ad0` hereda StringRequest, método 0 (GET), y fija User-Agent desde recurso
**0x7f12001d**, `string/app`, valor **Tx Tunnel**. `wc0.onResponse` abre el cuerpo
con DOO y comprueba Version/ReleaseNotes. No se usa la URL histórica distinta
que quedó como metadato inerte en `ultra.py`.

La petición exacta devuelve HTTP 200, 922944 bytes; Content-Type text/html es
el header del servidor, pero **el cuerpo es Base64 autenticado**, no una página
HTML. Se abre completo: versión **65.62**, **27 servidores / 643 redes / 4231
campos cifrados**. Asset: **2.0**, **23 / 66 / 657 campos**.

El origen del broker es literal y conserva sus comprobaciones DNS/TLS y de
redirecciones; el CLI autónomo rechaza todas las redirecciones. El worker solo
recibe bytes del broker. No acepta URL ni appcode arbitrarios del cliente.

## Integración y límites

`.tx` se actualiza como override C8; C0 240 y C8 250 se conservan. El bot
delega solo `.tx` al nuevo lector. Sus variantes históricas siguen usando la
implementación original. Dado que comparten la clave con el build 70, un campo
interno con tag inválido o JSON autenticado duplicado **no** puede caer al
lector permisivo y reaparecer cifrado como si fuera una lectura completa.

No se identificó exportación de texto propietaria ni cloud por token. El
texto adjunto es promocional; esquemas V2Ray estándar no son evidencia de
un formato nuevo. Se conserva el icono original, mínimo catálogo 40 / 40 fichas,
control individual y switches persistentes. No se modifican Android, C11 o VPS.
Pendiente `.tx` real; ni fixtures sintéticos ni catálogos sustituyen esa prueba.
