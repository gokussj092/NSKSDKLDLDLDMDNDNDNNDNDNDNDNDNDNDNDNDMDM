# RNV Tunnel VPN v1.9.28.1

Package `io.isvsoft.pub.rnvtunnelvpn`, versionCode 101, versionName
v1.9.28.1. App basada en v2rayNG + núcleo Sandok (com.sandok.tunnel.core),
con el núcleo Go en `libgojni.so` (AndroidLibXrayLite v2.5).

## Archivos

| Archivo | Descripción |
|---|---|
| `RNV_Tunnel_VPN.py` | Catálogo: descarga (POST) + descifrado Argon2id/AES-256-GCM. `decode()` + `run()` + CLI `--url`. |
| `RNV_Tunnel_VPN_archivos.py` | Decodificador de archivos de perfil `.rnv` (mismo sobre, clave K2). |
| `RNV_Tunnel_VPN.png` | Icono original del APK (`res/drawable/icon.png`), 512×512. |
| `configfile.json` | Asset incluido del APK (`assets/configfile.json`): catálogo de ejemplo cifrado con K2. Sirve para `--self-test`. |

Dependencias: Python 3.10+, solo biblioteca estándar. Argon2id (RFC 9106)
y AES-256-GCM están implementados en Python puro en los scripts
(verificados contra argon2-cffi y PyCryptodome). Un descifrado tarda
~15-20 s; el catálogo en vivo que no verifica puede tardar ~1 min
porque prueba ambas claves.

## Catálogo

Método recuperado del núcleo Go (`libgojni.so`,
`github.com/2dust/AndroidLibXrayLite.CU`). La app NO hace GET: hace un
POST con un campo de formulario.

```
POST https://strongteam.co/api/atnetvpn/
Content-Type: application/x-www-form-urlencoded
User-Agent: Go-http-client/1.1
Body: hash=xsandokBCUpdatex
```

Sin auth, sin cookies, sin más cabeceras. El servidor responde HTTP 200,
`Content-Type: text/plain`, cuerpo de una sola línea Base64 (942201 bytes
el 2026-11-13, determinista entre peticiones y User-Agents). El cuerpo es
un sobre Argon2id + AES-256-GCM (el mismo que produce `Encrypt()`):

```
Base64( salt[16] || nonce[12] || AES-256-GCM(key, nonce, AAD=salt) )
key = Argon2id(password, salt, time=3, memory=8192 KiB, threads=1, 32 B)
```

Dos contraseñas de 32 bytes en `libgojni.so` `.rodata` (constantes de
formato, no credenciales de cuenta):

- **K1** `55wM74DfCDIEaQ7nZPvsGmbw8qq6UFAh` — `decrypt()`/`Encrypt()`,
  la ruta del catálogo en vivo (CU llama a `decrypt` sobre la respuesta).
- **K2** `VENghqlinlpXUH5iVjNtL51WUqoeq/qB` — `DO()`/`do_()`, el asset
  incluido y las cadenas de archivos `.rnv`.

El JSON descifrado usa el esquema Sandok/Ultra (`Version`,
`ReleaseNotes`, `Telegram`, `WhatsApp`, `Facebook`, `DefOVPNUser`,
`DefOVPNPass`, `HysteriaUser`, `HysteriaOBFS`, `DefaultOVPNCert`,
`isTimerOn`, `timetoadd`, `Servers[]`, `Networks[]`), NO el esquema
XXTEA `Free_servers`/`Payloads` de los demás proveedores.

### Prueba real en vivo (2026-11-13)

- El endpoint responde HTTP 200 y el script descarga el cuerpo completo
  (942201 bytes, SHA-256 `f69ecdaf…`, idéntico al obtenido con curl).
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
python RNV_Tunnel_VPN.py --self-test
# {"self_test": "OK", "key": "K2", "version": "1.01", "servers": 1, "networks": 1}
```

Uso:

```
python RNV_Tunnel_VPN.py --url -o catalogo.json   # descarga en vivo
python RNV_Tunnel_VPN.py configfile.json           # asset incluido
```

Notas de descarga: Cloudflare trunca el cuerpo fragmentado en ~la mitad
de las peticiones (`IncompleteRead`) e ignora `Range` en este POST, así
que el script reintenta el POST completo hasta obtener el cuerpo entero
(en vez de reanudar por rangos). La descarga se hace con `http.client`
y túnel CONNECT explícito cuando hay proxy, porque `urllib` trunca el
cuerpo en este entorno. La URL de iconos es aparte y no es el catálogo:
`https://strongteam.co/nets/<nombre del icono>` (NetworkIconCache).

## Archivos `.rnv`

El manifest declara la importación `.rnv` (`application/x-rnv`,
`application/octet-stream`, `.*\.rnv`). Al importar, la app pasa el
contenido como texto por `Libv2ray.do_()` (`Hometab.Companion.a`): es el
mismo sobre Argon2id + AES-256-GCM con **K2**. El texto descifrado es el
JSON del perfil (mismo esquema `Servers`/`Networks`). Las protecciones
(contraseña, HWID, bloqueo de red) viven dentro del JSON y se verifican
después del descifrado.

**Verificación:** el sobre K2 está verificado contra la propia librería
de la app — `configfile.json` abre con K2 y el round-trip
cifrar/descifrar con K2 es exacto (incl. Unicode y CRLF). **Falta** la
confirmación de extremo a extremo con un `.rnv` real exportado por la
app en un teléfono (no existe ninguna muestra `.rnv` en este análisis).
Los archivos `.sks` están excluidos por indicación de Pedro y no se
implementan (esta app tampoco los usa).

```
python RNV_Tunnel_VPN_archivos.py perfil.rnv -o perfil.json
python RNV_Tunnel_VPN_archivos.py --self-test
```

## Textos/enlaces

**Sin esquema funcional propio de RNV.** Los esquemas del manifest son
los genéricos de v2rayNG (`v2rayng://install-config`,
`v2rayng://install-sub`). Los únicos prefijos `://` en la app son los
enlaces estándar de protocolos que SP-DECODE ya cubre (`vmess://`,
`vless://`, `trojan://`, `ss://`, `socks://`, `wireguard://`,
`hysteria2://`, `tuic://`, `hy2://`, `http://`); no hay un esquema
propio cifrado tipo `darktunnel://` que decodificar.

## Cobertura del repo

No existe proveedor RNV en `decoders/Python/apps/` (rama
`feat/nuevas-integraciones`, 86 proveedores). Las pistas de familia
fueron `RJC_TUNNEL_PRO` y `Ultra_Tunnel`, pero RNV usa un método
distinto (Go/Argon2id + AES-GCM, no XXTEA): el catálogo, el sobre y las
claves se verificaron contra ESTE APK (`libgojni.so` y
`assets/configfile.json`), no contra otro proveedor.
