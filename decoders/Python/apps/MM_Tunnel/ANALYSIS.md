# Reinvestigación vigente: MM Tunnel build47 — 2026-11-01

Prevalece sobre el análisis histórico del build45 que se conserva abajo.
Se trabaja con Goku en `fix/http-jireh-current-method`, sobre64ea621;
main5a1c93a no contiene esta rama. No se crea una rama desde un main anterior.
Alcance autorizado: resolver MM y reportar antes de continuar con CREEB.

Google Play consultado en vivo muestra **v1.10.30.2**. El XAPK de APKPure
coincide: build47, armeabi-v7a, minSDK32/targetSDK37. Signer SHA1
`b3d1c77b6cdb2f8b2c154c937de6b26669584d9a`; SHA256
`4cfc4aae2984b26da41ab2ec71000edf1e8f5a73a738292fd452235a9e6456c3`.
No se afirma una descarga directa desde Play. JADX1.5.6 terminó exit3 con78
errores generales; las rutas indicadas se recuperaron, no todo el APK.
LSParanoid:7706 cadenas en500 fuentes, inventario9738; no se publica.

En `libgojni.so` ARM32, Go pclntab f1 en0x12fadb8/textStart0x2efa08:
36934 funciones. `CU`0xfd7154(1696 bytes) construye url.Values con **hash**
(0x10d5b4,len4) y la constante original(0x118bef,len14); codifica formulario,
`NewRequestWithContext(POST,https://strongteam.co/api/mmtunnel/,reader)`,
Content-Type application/x-www-form-urlencoded y cliente HTTP nuevo con
User-Agent predeterminado Go-http-client/1.1. No añade sesión, Authorization,
cookies, firma ni metadatos de instalación en esta ruta.
El script anterior usaba **type**: recuperar una URL y una constante sin la
clave real del formulario dejó una integración incompleta.

La respuesta se abre con `decrypt`0xfd2e0c y contiene Version2.46,38/557.
`DO`0xfd3b58 conserva los parámetros y clave de campos del build45; la clave de
exportación tampoco cambia. `mm_tunnel_source_check.py` verifica los hashes
exactos y las instrucciones ARM de las cargas PC-relativas, sin ejecutar el APK.
`NetworkAdapter.v` mantiene la exportación .mmt; HomeFragment usa Info sin DO
y URI como Boolean, por lo que ahora se conservan y se limitan los contextos.

La recuperación, hashes, descargas reales, límites y separación entre pruebas
simuladas y producción están en el handoff de esta reintegración.

---

## Análisis histórico build45 (superado en descarga por la investigación anterior)

# Análisis de MM Tunnel — 2026-10-24

Rama nueva `feat/mm-tunnel-1-10-11-1-decoders`, creada desde `main`
`d6b28e532c97455b3e57a53dc7ec9d232f3a0d9c`. Se leyeron ARCHITECTURE, la guía
Server VPN, C8, el runbook de catálogos y las herramientas de recuperación.
No se encontraron `AGENTS.md` aplicables en el checkout ni sus ancestros.
La instrucción actual del usuario de crear una rama desde main sustituye la
preferencia histórica de continuar automáticamente el PR #96.

## Identidad y procedencia

| Pieza | SHA-256 |
|---|---|
| APKS, 43,171,381 bytes | `f97637e8101285914322863624d56690246701ad91a2df62538572a0c998f451` |
| base.apk | `603850284b1107517dd5fcda65e8737697dc63ac55963367d7619fb984df5e56` |
| libgojni.so ARM64, 30,749,584 bytes | `221b740acefe5ee6906e4db48f90f821afe3304bc7cfe5457cfe0860a698067b` |
| assets/configfile.json, 816,912 bytes | `ae4a7b72044b354826449700c031fc3da93dd94ae0834a083b3c828d5bb32880` |
| res/drawable/icon.png, 109,337 bytes | `be2bb0a69da20838aaa46c388ab898a33b84cab59ccdad7413b76eac21b7b211` |

Nombre MM Tunnel, paquete `co.strongteam.marvsudp`, versionName
`v1.10.11.1`, versionCode **45**. No confundir el nombre histórico «MMT TUNNEL»
del inventario genérico con la identidad verificada de este paquete.

## Evidencia DEX

JADX 1.5.6: DEX 1 termina con código 3 / 42 errores generales; DEX 2 con
código 3 / 31 errores. No se afirma que todo el APK esté descompilado.
LSParanoid: clase `Deobfuscator$MMTunnel$app` en DEX2. Se resuelven 253 cadenas
en 31 fuentes DEX1 y 7,377 en 461 fuentes DEX2; inventario de 9,667 cadenas.
Las herramientas no ejecutan clases del APK.

- `NetworkAdapter.u(int,String,String)`: volcado Dalvik de **116 instrucciones**;
  `Gson -> Libv2ray.encrypt -> nombre.mmt -> NetworkShareProvider`.
  MIME `application/x-mmt`; Android comparte un archivo y un texto promocional.
- `ConfigFileParser.onCreate`: lectura del archivo, `parseConfig(data)`;
  alternativa `JSONObject(Hometab.Companion.a(data))`. No hay argumento ni
  diálogo de contraseña en esta ruta.
- `Hometab.Companion.a`: llama `Libv2ray.do_`, conserva el texto ante excepción.
- `ServerStatusVIew.g` y `HomeFragment`: `MMCONFIGKEY1` o asset local, DO y Gson.
- `ConfigUpdate$configUpdate$1`: `cu(version)`, `gfc()`, `getVerNotes` y guardado
  del catálogo. Es catálogo de conexión, no solo metadatos de actualización APK.
- `NetworkIconCache` (`util/c.java`) descarga iconos desde `/nets/`; **no** es
  un segundo catálogo ni un almacén cloud de configuraciones de usuarios.
- `EConfigType` contiene los esquemas V2Ray estándar. No se encontró `mmt://`
  ni carga de perfiles a un cloud mediante token en la ruta de exportación.

## Evidencia Go y cifrado

Go pclntab f1 está fusionada dentro de `.data.rel.ro`, dirección **0x1401f20**.
La referencia relocalizada de moduledata fija textStart **0x5234b0**. Se recuperan
**36,659 funciones**. `go_inspect.py` ahora admite este layout de sección
fusionada y rechaza tablas ausentes o ambiguas, sin inventar textStart.

| Función `github.com/2dust/AndroidLibXrayLite.*` | Dirección | Bytes |
|---|---|---:|
| Encrypt | `0x1012110` | 768 |
| decrypt | `0x10124c0` | 576 |
| EO | `0x10129d0` | 672 |
| DO | `0x1012df0` | 720 |
| CU | `0x10158f0` | 1,360 |

Ambos métodos usan **Argon2id v19**, t=3, m=16,384 KiB, p=1, salida 32 bytes;
AES-256-GCM, nonce 12 bytes, tag 16 bytes y AAD igual al salt de 16 bytes.
Formato binario: `salt[16] || nonce[12] || ciphertext || tag[16]`.

`Encrypt` y `decrypt` usan la constante de 32 bytes referenciada en **0x365e74**,
codifican Base64 estándar e insertan/eliminan una letra ASCII en índice 3.
`EO`/`DO` usan otra constante fija de 21 bytes, construida desde **0x353439** y
un store solapado en +13; sin la letra insertada. Las constantes residen en el
codec, no se imprimen en diagnósticos. Ninguna procede de la contraseña del usuario.

El asset utiliza EO/DO exterior y en sus campos internos. El actualizador `CU`
abre su respuesta con `decrypt` (método de exportación). Las dos formas se
contrastan con documentos sintéticos independientes. No se aplica el intento
histórico sin AAD a los documentos de este build; esa alternativa se conserva
solo mediante el lector histórico para sus perfiles anteriores.

## Catálogo y límites de la comprobación

Asset versión 1.01: 34 servidores, 555 redes y 3,335 campos cifrados distintos.
El primer descifrado completo tardó **83.78 s** en este entorno y produjo
485,107 bytes UTF-8. El presupuesto de catálogo existente es 120 s; la latencia
de otros entornos puede variar. No se amplían los límites de otros proveedores.
La caché local por documento no persiste valores tras la petición.

`CU` fija POST `https://strongteam.co/api/mmtunnel/` con formulario
`type=xsandokUpdatex`. Dos peticiones con ese formulario devolvieron HTTP 403
JSON. No se afirma el motivo de la restricción ni que el servicio esté caído.
El lector remoto queda preparado pero sin habilitar el broker público.

Las pruebas con fixtures demuestran paridad criptográfica y del JSON completo;
no sustituyen una exportación `.mmt` real ni una importación en teléfono. No se
publican APK/SO/DEX, catálogos, credenciales o inventarios de cadenas reales.
