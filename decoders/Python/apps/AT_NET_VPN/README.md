# AT NET VPN v1.9.28.1

Package `com.technore.atnetvpn`, versionCode 103, versionName
v1.9.28.1. App basada en v2rayNG + núcleo Sandok (com.sandok.tunnel.core),
con el núcleo Go en `libgojni.so` (AndroidLibXrayLite v2.5). Es la app
hermana de RNV Tunnel VPN v1.9.28.1 (`io.isvsoft.pub.rnvtunnelvpn`,
build 101): misma versión, mismo núcleo Go, mismo endpoint de catálogo
y las mismas dos claves de formato. El método se verificó contra ESTE
APK (su propio `libgojni.so` y su propio `assets/configfile.json`), no
solo contra RNV.

## Archivos

| Archivo | Descripción |
|---|---|
| `AT_NET_VPN.py` | Catálogo: descarga (POST) + descifrado Argon2id/AES-256-GCM. `decode()` + `run()` + CLI `--url`. |
| `AT_NET_VPN_archivos.py` | Decodificador de archivos de perfil `.atnet` (mismo sobre, clave K2). |
| `AT_NET_VPN.png` | Icono original del XAPK (`icon.png`), 512×512. |
| `configfile.json` | Asset incluido del APK (`assets/configfile.json`): catálogo de ejemplo cifrado con K2. Sirve para `--self-test`. Es byte a byte idéntico al de RNV Tunnel VPN v1.9.28.1 (mismo SHA-256). |

Dependencias: Python 3.10+, solo biblioteca estándar. Argon2id (RFC 9106)
y AES-256-GCM están implementados en Python puro en los scripts
(verificados contra argon2-cffi y PyCryptodome). Un descifrado tarda
~15-20 s; el catálogo en vivo que no verifica puede tardar ~1 min
porque prueba ambas claves.

## Catálogo

Método recuperado del núcleo Go de ESTE APK (`libgojni.so`,
`github.com/2dust/AndroidLibXrayLite.CU`): la app NO hace GET, hace un
POST con un campo de formulario.

```
POST https://strongteam.co/api/atnetvpn/
Content-Type: application/x-www-form-urlencoded
User-Agent: Go-http-client/1.1
Body: hash=xsandokBCUpdatex
```

Sin auth, sin cookies, sin más cabeceras. El servidor responde HTTP 200,
`Content-Type: text/plain`, cuerpo de una sola línea Base64 (942185 bytes
el 2026-11-13). El cuerpo es un sobre Argon2id + AES-256-GCM (el mismo
que produce `Encrypt()`):

```
Base64( salt[16] || nonce[12] || AES-256-GCM(key, nonce, AAD=salt) )
key = Argon2id(password, salt, time=3, memory=8192 KiB, threads=1, 32 B)
```

Dos contraseñas de 32 bytes en `libgojni.so` de ESTE APK (constantes de
formato, no credenciales de cuenta; file offsets 0x365dee y 0x365e0e —
RNV Tunnel VPN v1.9.28.1 tiene las mismas dos constantes en 0x365df4 y
0x365e14):

- **K1** `55wM74DfCDIEaQ7nZPvsGmbw8qq6UFAh` — `decrypt()`/`Encrypt()`,
  la ruta del catálogo en vivo (CU llama a `decrypt` sobre la respuesta).
- **K2** `VENghqlinlpXUH5iVjNtL51WUqoeq/qB` — `DO()`/`do_()`, el asset
  incluido y las cadenas de archivos `.atnet`.

El JSON descifrado usa el esquema Sandok/Ultra (`Version`,
`ReleaseNotes`, `Telegram`, `WhatsApp`, `Facebook`, `DefOVPNUser`,
`DefOVPNPass`, `HysteriaUser`, `HysteriaOBFS`, `DefaultOVPNCert`,
`isTimerOn`, `timetoadd`, `Servers[]`, `Networks[]`), NO el esquema
XXTEA `Free_servers`/`Payloads` de los demás proveedores.

### Prueba real en vivo (2026-11-13)

- El endpoint responde HTTP 200 y el script descarga el cuerpo completo
  (942185 bytes, SHA-256
  `950062e7ffdc0a36f0629591b397e36ae5c0b0c932db63c84de02cb6355abb46`,
  una sola línea Base64). El cuerpo varía ligeramente entre peticiones
  (la captura de RNV el mismo día fue de 942201 bytes,
  SHA-256 `f69ecdaf…`).
- **El cuerpo en vivo NO verifica con K1 ni con K2.** Se probaron
  Argon2i, ChaCha20-Poly1305, XXTEA/Princie!, scrypt, otros layouts de
  salt/nonce y una rejilla de parámetros Argon2: ninguno abre el tag
  GCM. El servidor parece haber rotado la clave/formato del catálogo en
  vivo después de esta versión del APK, o el payload en vivo usa una
  clave que no está en v1.9.28.1. El script lo reporta como
  `LIVE_DECRYPT_FAILED` en vez de afirmar un descifrado falso.
- El asset incluido **sí abre con K2** (verificado: tag GCM auténtico,
  JSON válido, Version `1.01`, 1 Server, 1 Network):

```
python AT_NET_VPN.py --self-test
# {"self_test": "OK", "key": "K2", "version": "1.01", "servers": 1, "networks": 1}
```

Uso:

```
python AT_NET_VPN.py --url -o catalogo.json   # descarga en vivo
python AT_NET_VPN.py configfile.json           # asset incluido
```

Notas de descarga: Cloudflare trunca el cuerpo fragmentado en ~la mitad
de las peticiones (`IncompleteRead`) e ignora `Range` en este POST, así
que el script reintenta el POST completo hasta obtener el cuerpo entero
(en vez de reanudar por rangos). La descarga se hace con `http.client`
y túnel CONNECT explícito cuando hay proxy, porque `urllib` trunca el
cuerpo en este entorno. La URL de iconos es aparte y no es el catálogo:
`https://strongteam.co/nets/<nombre del icono>` (NetworkIconCache).

## Archivos `.atnet`

El manifest declara la importación `.atnet`
(`application/x-atnet`, `application/octet-stream`,
`.*\.atnet`). Al importar, `ConfigFileParser`
(`com/v2ray/ang/ui/ConfigFileParser.java`) lee el archivo como texto
UTF-8; si `Libv2ray.parseConfig()` lo rechaza como config v2ray plano,
pasa por `Hometab.Companion.a` (`com/v2ray/ang/Hometab.java`), que llama
a `Libv2ray.do_()` (el Go `DO()` de `libgojni.so`) y, si `do_()` falla,
devuelve el texto tal cual. `do_()` es el mismo sobre Argon2id +
AES-256-GCM con **K2**. El texto descifrado es el JSON del perfil (mismo
esquema `Servers`/`Networks`). Las protecciones (contraseña, HWID,
bloqueo de red) viven dentro del JSON y se verifican después del
descifrado.

**Verificación:** el sobre K2 está verificado contra la propia librería
de la app — `configfile.json` abre con K2 y el round-trip
cifrar/descifrar con K2 es exacto (incl. Unicode y CRLF; también por
CLI: un `.atnet` sintético cifrado con K2 se abre como Version 1.01,
1 Server, 1 Network). **Falta** la confirmación de extremo a extremo
con un `.atnet` real exportado por la app en un teléfono (no existe
ninguna muestra `.atnet` en este análisis). Los archivos `.sks` están
excluidos por indicación de Pedro y no se implementan (esta app tampoco
los usa).

```
python AT_NET_VPN_archivos.py perfil.atnet -o perfil.json
python AT_NET_VPN_archivos.py --self-test
```

## Textos/enlaces

**Sin esquema funcional propio de AT NET.** Los esquemas del manifest
son los genéricos de v2rayNG (`v2rayng://install-config`,
`v2rayng://install-sub`). Los únicos prefijos `://` en la app son los
enlaces estándar de protocolos que SP-DECODE ya cubre (`vmess://`,
`vless://`, `trojan://`, `ss://`, `socks://`, `wireguard://`,
`hysteria2://`, `tuic://`, `hy2://`, `http://`); no hay un esquema
propio cifrado tipo `darktunnel://` que decodificar.

## Cobertura del repo

No existe proveedor AT NET en `decoders/Python/apps/` (rama
`feat/nuevas-integraciones`, 86 proveedores). La única mención de
`technore` en el repo es la clave `technore_008515` del proveedor
24clan_VPN_Green (otra app, otro formato). El catálogo, el sobre y las
claves se verificaron contra ESTE APK (`libgojni.so`,
`assets/configfile.json`, `ConfigFileParser.java`, `Hometab.java`),
no contra otro proveedor.
