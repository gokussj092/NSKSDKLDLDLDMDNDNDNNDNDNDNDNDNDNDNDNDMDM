# RJC Tunnel VPN RJC-19

Paquete `com.rjctunnel.vpn`, versionCode 19, versionName RJC-19.
Python 3.10+, solo biblioteca estándar; no requiere APK ni librerías nativas
al ejecutar.

```bash
python RJC_Tunnel_VPN.py --url > catalogo.json
python RJC_Tunnel_VPN.py --url https://raw.githubusercontent.com/pipoyrichards/RJCTUNNEL/refs/heads/main/FEBRUARY > catalogo.json
python RJC_Tunnel_VPN.py copia-cifrada > catalogo.json
python RJC_Tunnel_VPN.py --stdin < copia-cifrada > catalogo.json
python RJC_Tunnel_VPN.py gremlin.json > catalogo.json   # asset o copia local
```

`decode(data: bytes | str) -> dict` descifra offline; `run(data) -> str | None`
devuelve el JSON completo o `None` sin lista parcial. La salida es el
documento completo: `Version`, `Changelogs`, `Username`, `Password`,
`Free_servers`, `Premium_servers`, `Vip_servers`, `Private_servers`,
`Payloads` y propiedades desconocidas. Entrada/salida limitadas a 8 MiB.

## Método de catálogo (verificado en el DEX de ESTE APK)

- Descarga: `OpenVPNClient.z()` crea una petición `NW` (pila HTTP propia,
  equivalente a Volley) con la URL fija y la encola con
  `AbstractC4578yf0.B(context)`. La pila (`C3797ow`, `HttpURLConnection`)
  emite un **GET** sin cuerpo, sin parámetros, sin autenticación y sin
  cabeceras propias, con `User-Agent: datatransport/3.3.0 android/`,
  timeouts de conexión/lectura de 2500 ms y caché desactivada.
- Endpoint:
  `https://raw.githubusercontent.com/pipoyrichards/RJCTUNNEL/refs/heads/main/FEBRUARY`
- Respuesta: el callback `HJ.e()` quita espacios y saltos de línea y descifra
  con `AbstractC0333Mm.c(respuesta, AbstractC0333Mm.a)`:
  **Base64 estándar → XXTEA, delta `0x9e5729b1` (-1638454863), clave de
  formato truncada/rellenada a 16 bytes, palabras little-endian y tráiler de
  longitud** (idéntico a `AbstractC0333Mm.b/d`; `e()` es el cifrado inverso).
- La app comprueba que la `Version` remota sea mayor que la local
  (`OpenVPNClient.w`), fusiona los payloads locales "Custom Tweak" en
  `Payloads` y guarda el resultado **recifrado con la misma clave XXTEA**
  en `filesDir/gremlin.json` (`AbstractC0240Iw.X` = `AbstractC0333Mm.e`).
  La lectura local (`a.m()`) usa el mismo descifrado, con fallback al asset
  `gremlin.json` si no existe copia local. Este script devuelve el documento
  remoto tal cual, sin fusionar perfiles locales (igual que el decodificador
  de RJC TUNNEL PRO).

## ¿Comparte método con RJC TUNNEL PRO (RJC-6, `com.rjct.pro`)?

**Sí en cifrado, no en endpoint.** La receta es idéntica — mismo Base64 →
XXTEA con delta `0x9e5729b1` y la misma clave de formato de 7 caracteres
(`AbstractC0333Mm.a` = la clave de `AbstractC0015Mm` / Mx Tunnel PRO,
verificada por igualdad directa tras resolver las cadenas LSParanoid) — y el
asset `gremlin.json` incluido en este APK es byte a byte el mismo que el de
RJC-6 (mismo SHA-256, misma versión 15.1). Lo único distinto es el
**repositorio del catálogo**: RJC-19 descarga de
`pipoyrichards/RJCTUNNEL` y RJC-6 de `pipoyrichards/RJCPRO`
(misma rama `main`, mismo archivo `FEBRUARY`). Las cadenas de la app están
ofuscadas con LSParanoid (`Deobfuscator$MHRTUNNELVPN$app`, 1811 IDs
resueltos con la implementación de referencia `paranoid-deobfuscator`).

## Validación real (2026-11-13)

| Fuente | Bytes cifrados | SHA-256 (primeros 16) | Versión | Servidores libres | Payloads |
| --- | ---: | --- | --- | ---: | ---: |
| HTTPS `--url`, HTTP 200 | 783952 | `20dfb413686397c6` | 23 | 41 | 1258 |
| Asset `gremlin.json` del APK | 744904 | `520e2aa7fa07a312` | 15.1 | 46 | 1205 |

Premium/Vip/Private: 0 en ambas. El JSON renderizado por este script es
byte a byte idéntico al producido por el codec compartido del repo
(`RJC_TUNNEL_PRO/codec.py` → `Mx_Tunnel_PRO/codec.py`) sobre las mismas
entradas. Entrada inválida → exit 1 con `{"error": ...}` en stderr y sin
salida parcial.

## Archivos `.rjc` — incluido (verificado contra `libputils.so`)

La app importa/exporta perfiles como archivos `.rjc` (`AndroidManifest`:
`ImportTweakActivity`, `content`/`file`, `.*\.rjc`; exportación a
`Downloads/RJCTUNNEL/<nombre>.rjc`). El contenido es la primera línea del
archivo pasada por `PUtils.pDecrypt/pEncrypt` (`OpenVPNClient.onCreate`
con `ACTION_VIEW` y `onActivityResult` 1001), que devuelve un JSON con
`tweak_password` (vacío → importación directa `B()`; con valor → pide la
contraseña en `Z()` y luego `B()`), con controles de caducidad, HWID
(`F()`, huella del dispositivo) y bloqueo por operador. El tweak importado
se añade como payload "Custom Tweak" al `gremlin.json` local.

**Verificado:** la `libputils.so` propia de RJC-19 (extraída del split
arm64 del `.apks`) contiene `pDecrypt` en 0x149c54 = `hexToString` →
`xorWithKey` con una clave de 12 bytes en `.rodata` 0xc505e. El
decodificador `RJC_Tunnel_VPN_archivos.py` usa esa clave: hex en
minúsculas → XOR (clave 12 B) → UTF-8 JNI modificado → JSON. Round-trip
6/6 y, como prueba con datos reales, el asset `server.psi` del APK
recupera 22 de 23 objetos JSON válidos con esa clave. Queda pendiente
solo la confirmación extremo a extremo con un `.rjc` real exportado por
la app; no hay archivos `.rjc` de muestra en el repo SP-DECODE.

## Textos/enlaces — NO hay esquema propio

- `rjc://` aparece **una sola vez** en todo el código decompilado, como una
  llamada descartada en el constructor de `OpenVPNClient` (valor no usado,
  sin `intent-filter`, sin `startsWith`/`contains` ni parseo). Es una
  cadena muerta, no un esquema de importación.
- No hay `ACTION_SEND`, ni lectura de portapapeles para importar, ni
  `intent-filter` con esquema propio en el manifest (solo `content`/`file`
  + `.*\.rjc`). Los `vmess://` del código son plantillas de configuración
  XRay generadas por la app, no enlaces de importación.
- Por eso no se entrega `RJC_Tunnel_VPN_textos.py`.

## Procedencia

- APK: `apk/base.apk`, 18 MB,
  SHA-256 `c71376714fccd659beb46081e812a28dab2c266032ba288779853b13c5b2c6c7`
- Icono: `RJC_Tunnel_VPN.png`, PNG original exacto de
  `res/drawable/ic_app_icon.png`, 512×512, 26722 bytes, sin recodificar,
  SHA-256 `ca1db272e52691f9fd4567ee9b39af9459098ca23636dec1ac11bcb26ea3cfab`
- Script: `RJC_Tunnel_VPN.py`,
  SHA-256 `cfef12bd96399acdfc95cf558d4b6b2d036118cf2ca83ca705b48a494cbe8ae5`
- Descarga remota de referencia guardada en `work/remote-FEBRUARY.bin`
  (783952 bytes, SHA-256
  `20dfb413686397c63d792b418e017da7c29d4549ee3696a0c0dc860832baa46b`)
- Decompilación en `jadx-out/` (jadx 1.5.3, 37 errores menores de
  decompilación, clases `rjc.*` completas); cadenas LSParanoid resueltas en
  `work/strings.json` (1811 IDs) con `work/lsparanoid.py` (parseo de chunks)
  + `paranoid-deobfuscator` 3.0.2.

## Contrato de salida

`decode()`/`run()` devuelven el documento completo del catálogo o fallan sin
parciales. El script nunca mezcla perfiles locales ni inventa credenciales.
La fusión de "Custom Tweak" locales que hace la app al actualizar queda
fuera del alcance: es estado del teléfono, no parte de la descarga.

## Pendientes

1. `.rjc`: confirmación extremo a extremo con una muestra `.rjc` real
   exportada por la app (el método ya está verificado contra la
   `libputils.so` propia).
2. `rjc://`: confirmar en el teléfono que ningún enlace con ese esquema
   abre la app (el código y el manifest dicen que no).
