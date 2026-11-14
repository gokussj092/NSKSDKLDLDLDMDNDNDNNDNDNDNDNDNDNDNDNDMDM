# REG Tunnel VPN v1.9.28.1 — decodificador de catálogo y archivos `.reg`

Package `io.isvsoft.pub.regtunnelvpn`, versionCode 101, versionName v1.9.28.1,
minSdk 32. App: REG Tunnel VPN. Analizada en su versión pública de Google Play
(APKPure, XAPK arm64-v8a, 54.479.819 B, SHA-256
`b65403b1ff1a64e178de305261be97c638babe380609633f49581cf5ca57e629`, coincide
exacto con el publicado por APKPure).

## Resultado en vivo: catálogo indescifrable (fallo honesto, como RNV/AT NET)

REG Tunnel es de la misma familia StrongTeam que RNV Tunnel VPN (tanda 3) y
AT NET VPN (tanda 5): mismo núcleo Go (`libgojni.so`, `AndroidLibXrayLite`),
mismas claves K1/K2, mismo cuerpo `hash=xsandokBCUpdatex`. La única diferencia
es el endpoint: **`/api/regtunnel/`** en vez de `/api/atnetvpn/`.

- Catálogo: `POST https://strongteam.co/api/regtunnel/`,
  `Content-Type: application/x-www-form-urlencoded`,
  `User-Agent: Go-http-client/1.1`, cuerpo `hash=xsandokBCUpdatex`.
- Respuesta en vivo (2026-11-14, dos descargas): HTTP 200, cuerpo Base64 de
  **905.541 B** (SHA-256
  `d13d3df0777b4bde653abe9b9c321b03fe9b7ffe13f4918381ebaf1f16928ff1`,
  determinístico entre peticiones), pero **NO verifica con K1 ni K2**
  (tampoco Argon2i, ChaCha20-Poly1305, XXTEA/Princie!, scrypt, otros layouts
  ni rejilla de parámetros Argon2). El servidor parece haber rotado la clave
  del catálogo en vivo tras v1.9.28.1, igual que RNV y AT NET.
- El script lo reporta como `LIVE_DECRYPT_FAILED` (sale con código 1) en
  vez de inventar servidores. Si el servidor vuelve a servir un sobre K1/K2,
  el script lo abre sin cambios.

## Método (verificado en ESTE APK, nada reutilizado sin verificar)

Sobre: `Base64( salt[16] || nonce[12] || AES-256-GCM(key, nonce, AAD=salt) )`,
clave = Argon2id(password, salt, time=3, memory=8192 KiB, threads=1, 32 B).
Esquema Sandok/Ultra (`Servers[]`/`Networks[]`).

Claves (constantes de formato, no credenciales), en `libgojni.so` `.rodata`,
en los mismos offsets que RNV/ATNET:

- K1 `55wM74DfCDIEaQ7nZPvsGmbw8qq6UFAh` (offset 0x365df4) — `decrypt()`/
  `Encrypt()`, catálogo en vivo.
- K2 `VENghqlinlpXUH5iVjNtL51WUqoeq/qB` (offset 0x365e14) — `DO()`/`do_()`,
  asset y archivos `.reg`.

El asset incluido `assets/configfile.json` es **byte por byte idéntico al de
RNV** (SHA-256 `b7e47d6e…`) y abre con K2: Version 1.01, 1 Server, 1 Network
(tag GCM auténtico). Las claves de Marvs SSH/T20-VPN NO están en esta
librería.

Petición exacta replicada en el script (http.client + túnel CONNECT, como
RNV): urllib trunca el cuerpo fragmentado; Cloudflare ignora `Range` en
este POST, así que el script reintenta el POST completo hasta 8 veces.

## Archivos `.reg`

El manifest declara la importación `.reg` (`application/x-reg`,
`application/octet-stream`, `.*\.reg`) en `ConfigFileParser` (acción VIEW).
Al importar, la app lee el archivo como texto: si `Libv2ray.parseConfig(str)`
lo acepta, sigue la ruta V2Ray; si no, pasa por `Hometab.Companion.a(str)` →
`Libv2ray.do_(str)` (si falla, devuelve el texto tal cual) y lo interpreta
como JSON (verificado en el DEX descompilado de ESTE APK:
`ConfigFileParser.java:101`, `Hometab.java:154`). La exportación usa
`Libv2ray.encrypt(Gson(NetworkList))` (`NetworkAdapter.java:245`).

`REG_Tunnel_VPN_archivos.py` abre `.reg` con K2 (y K1 como respaldo), mismo
sobre que el catálogo. Los archivos `.sks` están EXCLUIDOS por indicación de
Pedro (esta app tampoco los usa).

## Textos

Sin esquema URI propio: solo `v2rayng://` genérico (`install-config`,
`install-sub`) en `UrlSchemeActivity`, más `text/plain` por SEND. Los enlaces
estándar vmess/vless/ss/trojan ya los cubre SP-DECODE.

## Archivos

| Archivo | Descripción |
|---|---|
| `REG_Tunnel_VPN.py` | Decodificador de catálogo (stdlib puro; `--url`/`--file`/`--stdin`/`--self-test`/`-o`). SHA-256 `8d883bd4…` |
| `REG_Tunnel_VPN_archivos.py` | Decodificador `.reg` (stdlib puro; K2 + K1). SHA-256 `24b4e2bb…` |
| `REG_Tunnel_VPN.png` | Icono 512×512 RGBA (del XAPK). SHA-256 `8ee9e316…` |
| `configfile.json` | Asset incluido (abre con K2; `--self-test`). SHA-256 `b7e47d6e…` |
| `catalog_sample.b64` | Cuerpo vivo que NO abre (905.541 B, SHA-256 `d13d3df0…`) |
| `README.md` | Este archivo |

## Verificación

- `py_compile` OK en ambos scripts.
- `REG_Tunnel_VPN.py --self-test`: OK (K2, v1.01, 1 servidor, 1 red).
- `REG_Tunnel_VPN_archivos.py --self-test`: OK (K2, v1.01, 1 servidor, 1 red).
- Round-trip cifrar/descifrar exacto con K1 y con K2 (perfil sintético).
- `REG_Tunnel_VPN.py --url` en vivo (2 veces): descarga completa (905.541 B)
  + `LIVE_DECRYPT_FAILED` honesto.
- `REG_Tunnel_VPN.py catalog_sample.b64`: mismo fallo consistente.
- Sin cobertura previa en el repo SP-DECODE (clon sparse
  `feat/nuevas-integraciones`, 86 apps; sin carpeta de REG Tunnel ni
  menciones a `regtunnel`).

## Pendiente

Un archivo `.reg` real exportado por la app en un teléfono cerraría la
verificación extremo a extremo del decodificador de archivos (el sobre K2
ya está verificado contra el asset incluido y por round-trip). Si el
servidor vuelve a servir un sobre K1/K2, el catálogo vivo se abrirá con
estos mismos scripts sin cambios.
