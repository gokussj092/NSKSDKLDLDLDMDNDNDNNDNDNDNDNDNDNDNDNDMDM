# JetRoi (BC Net Lite) v1.9.28.1 — decodificador de catálogo y archivos `.bccnet`

Package `co.strongteam.jetroi`, versionCode 13, versionName v1.9.28.1,
minSdk 32. En Google Play y APKPure la ficha se titula "BC Net Lite",
desarrollador sando--k. Analizada en su versión pública de Google Play
(APKPure, XAPK **armeabi-v7a** de 32 bits, 53.485.599 B, SHA-256
`14963b4a107710a3c7a0def812a4022b1cb9258e5825073aabae2e683feec4ab` y SHA-1
`753f7972d04d2a08014c7fa183e66d429c562aca`, ambos coinciden exacto con los
publicados por APKPure). Pedro eligió la variante armeabi-v7a porque
APKPure no ofrece arm64 para esta versión.

## Resultado en vivo: catálogo indescifrable (fallo honesto, como RNV/AT NET/Marvs/REG)

JetRoi es de la misma familia StrongTeam que RNV Tunnel VPN (tanda 3),
AT NET VPN (tanda 5), Marvs SSH / T20-VPN (tanda 10a) y REG Tunnel
(tanda 10b): mismo núcleo Go (`libgojni.so`, `AndroidLibXrayLite`),
mismas claves K1/K2, mismo cuerpo `hash=xsandokBCUpdatex`. La única
diferencia es el endpoint: **`/api/bcnetlite/`** en vez de `/api/atnetvpn/`,
`/api/regtunnel/` o `/api/t20/`.

- Catálogo: `POST https://strongteam.co/api/bcnetlite/`,
  `Content-Type: application/x-www-form-urlencoded`,
  `User-Agent: Go-http-client/1.1`, cuerpo `hash=xsandokBCUpdatex`.
- Respuesta en vivo (2026-11-14, dos descargas): HTTP 200, cuerpo Base64 de
  **822.913 B** (SHA-256
  `8699dcdc8c3b667671fc0ba858a8578e25c144259899523b4aaebcf6b059df16`,
  determinístico entre peticiones), pero **NO verifica con K1 ni K2**
  (tampoco Argon2i, ChaCha20-Poly1305, las claves K1/K2 de Marvs SSH,
  Argon2 m=16384/4096, t=1/2, ni layout con el tag antes del cifrado;
  26 intentos, 0 aperturas). El servidor parece haber rotado la clave
  del catálogo en vivo tras v1.9.28.1, igual que RNV, AT NET, Marvs y REG.
- El script lo reporta como `LIVE_DECRYPT_FAILED` (sale con código 1) en
  vez de inventar servidores. Si el servidor vuelve a servir un sobre K1/K2,
  el script lo abre sin cambios.

## Método (verificado en ESTE APK, nada reutilizado sin verificar)

Sobre: `Base64( salt[16] || nonce[12] || AES-256-GCM(key, nonce, AAD=salt) )`,
clave = Argon2id(password, salt, time=3, memory=8192 KiB, threads=1, 32 B).
Esquema Sandok/Ultra (`Servers[]`/`Networks[]`).

Claves (constantes de formato, no credenciales), en el `libgojni.so` de
32 bits (split `config.armeabi_v7a.apk`, `.rodata`, VA = offset de archivo),
en los mismos valores y el mismo orden que RNV/AT NET/REG:

- K1 `55wM74DfCDIEaQ7nZPvsGmbw8qq6UFAh` (offset 0x1356a4) — `decrypt()`/
  `Encrypt()`, catálogo en vivo.
- K2 `VENghqlinlpXUH5iVjNtL51WUqoeq/qB` (offset 0x1356c4) — `DO()`/`do_()`,
  asset y archivos `.bccnet`.

K2 está VERIFICADA funcionalmente en ESTE APK: el asset incluido
`assets/configfile.json` abre con K2 (tag GCM auténtico, Version 1.01,
1 Server, 1 Network). El endpoint y el cuerpo `hash=xsandokBCUpdatex`
también se recuperaron de ESTE `libgojni.so` (offsets 0x13ca85 y 0x11b49e).
Un chequeo de referencias por desensamblado (MOVW/MOVT) fue inconcluyente
en este build de 32 bits (solo 8 instrucciones MOVT en `.text`; las
direcciones se cargan probablemente por literal pools), así que el uso de
las claves se apoya en la prueba funcional del asset más el layout
idéntico de la familia, no en un xref de desensamblado.

El asset incluido `assets/configfile.json` es **byte por byte idéntico al de
RNV y REG Tunnel** (SHA-256 `b7e47d6e…`) y abre con K2. Las claves de Marvs
SSH/T20-VPN NO están en esta librería. Todas las librerías nativas están
en el split armeabi-v7a (`libgojni.so`, `libovpncli.so`, `libtun2socks.so`,
`libpdnsd.so`, `libdns.so`, `libsocks.so`, `libuz.so`, `libmmkv.so`,
`libconscrypt_jni.so`, `libdatastore_shared_counter.so`,
`libimage_processing_util_jni.so`, `libsurface_util_jni.so`); el APK base
no trae ninguna `.so`.

Petición exacta replicada en el script (http.client + túnel CONNECT, como
RNV/REG): urllib trunca el cuerpo fragmentado; el script reintenta el POST
completo hasta 8 veces.

## Archivos `.bccnet`

El manifest declara la importación `.bccnet` (`application/x-bccnet`,
`application/octet-stream`, `.*\.bccnet`) en `ConfigFileParser` (acción
VIEW). Al importar, la app lee el archivo como texto: si
`Libv2ray.parseConfig(str)` lo acepta, sigue la ruta V2Ray; si no, pasa
por `Hometab.Companion.a(str)` → `Libv2ray.do_(str)` y lo interpreta como
JSON (verificado en el DEX de ESTE APK con androguard: `ConfigFileParser`,
`Hometab$Companion.a` y `Libv2ray.do_/parseConfig/encrypt` existen en
`classes2.dex`; `NetworkAdapter.u` → `Libv2ray.encrypt` para exportar;
la clase LSParanoid es `Deobfuscator$BCNetLite$app`). La exportación usa
`Libv2ray.encrypt(Gson(NetworkList))`.

`JetRoi_archivos.py` abre `.bccnet` con K2 (y K1 como respaldo), mismo
sobre que el catálogo. Los archivos `.sks` están EXCLUIDOS por indicación
de Pedro (esta app tampoco los usa).

## Textos

Sin esquema URI propio: solo `v2rayng://` genérico (`install-config`,
`install-sub`) en `UrlSchemeActivity`, más `text/plain` por SEND. Los
enlaces estándar vmess/vless/ss/trojan ya los cubre SP-DECODE.

## Archivos

| Archivo | Descripción |
|---|---|
| `JetRoi.py` | Decodificador de catálogo (stdlib puro; `--url`/`--file`/`--stdin`/`--self-test`/`-o`). SHA-256 `e0297093…` |
| `JetRoi_archivos.py` | Decodificador `.bccnet` (stdlib puro; K2 + K1). SHA-256 `c0502116…` |
| `JetRoi.png` | Icono 512×512 RGBA (del XAPK, ya era 512×512). SHA-256 `7744f49f…` |
| `configfile.json` | Asset incluido (abre con K2; `--self-test`). SHA-256 `b7e47d6e…` |
| `catalog_sample.b64` | Cuerpo vivo que NO abre (822.913 B, SHA-256 `8699dcdc…`) |
| `README.md` | Este archivo |

## Verificación

- `py_compile` OK en ambos scripts.
- `JetRoi.py --self-test`: OK (K2, v1.01, 1 servidor, 1 red).
- `JetRoi_archivos.py --self-test`: OK (K2, v1.01, 1 servidor, 1 red).
- Round-trip cifrar/descifrar exacto con K1 y con K2 (perfil sintético);
  un `.bccnet` sintético (K2) abre por CLI.
- `JetRoi.py --url` en vivo: descarga completa (822.913 B) +
  `LIVE_DECRYPT_FAILED` honesto, reproducido por el propio script.
- Rejilla sobre el cuerpo vivo: 26 intentos (K1/K2, Argon2i, m=16384/4096,
  t=1/2, ChaCha20-Poly1305, claves de Marvs, layout tag-first), 0 aperturas.
- Sin cobertura previa en el repo SP-DECODE (clon sparse
  `feat/nuevas-integraciones`, 86 apps; sin carpeta de JetRoi ni menciones
  a `jetroi`/`bcnet`).

## Pendiente

Un archivo `.bccnet` real exportado por la app en un teléfono cerraría la
verificación extremo a extremo del decodificador de archivos (el sobre K2
ya está verificado contra el asset incluido y por round-trip). Si el
servidor vuelve a servir un sobre K1/K2, el catálogo vivo se abrirá con
estos mismos scripts sin cambios.
