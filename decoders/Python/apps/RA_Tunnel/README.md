# RA Tunnel Lite — org.ratunnellite.xyz

**App:** RA Tunnel Lite · **Paquete:** `org.ratunnellite.xyz` · **Versión:** 1.3
(build 13, minSdk 24) · **Familia:** RENZ · **Estado: ✅ CATÁLOGO VIVO
DESCIFRADO Y VERIFICADO**

XAPK analizado: `RA_Tunnel_Lite_1.3_APKPure.xapk` (66,019,827 B,
SHA-256 `60e4c0fddc59d0e421c5292ac47bf008f57cd692224146e4cd7aad9fed6edb1a`).
El repo SP-DECODE **no tenía** cobertura de esta app (sin carpeta RA Tunnel
ni perfil `ratunnel` en `renz.py`).

## Catálogo en vivo (verificado 2026-11-14)

- **URL:** `https://rajonvipnet.xyz/uploads/json/ce5941b7a22b0ee3e1c1.json`
- **Petición:** GET simple (Volley `StringRequest`), sin cabeceras ni cuerpo.
  User-Agent de Volley/Dalvik (`Dalvik/2.1.0 (Linux; U; Android …)`):
  el host está tras Cloudflare y responde **403 a un UA genérico de curl**,
  así que el UA Dalvik es obligatorio.
- **Respuesta:** una sola línea Base64 (125,932 B → 94,448 B).
- **Versión del catálogo:** `334` · **Notes:** `Update Successful ✅`
- **Servidores: 12** — 5 OpenVPN (proto 0), 2 UDP (proto 2), 4 V2Ray/WS
  (proto 3), 1 proto 4. Dos llevan "VIP" en el nombre
  (`VIP UDP SERVER (01)`, `VIP SERVER 01`); el catálogo **no trae campo
  IsPremium**, así que no se puede distinguir gratis/premium por dato:
  los 12 vienen en la misma lista.
- **Networks (configs): 147** — 50 con campo `Payload` (28 distintos),
  83 con `SNIHost`. **SSLNetworks: 0.**
- **Credenciales del catálogo (descifradas):** usuario
  `renzbarbz@gmail.com`, contraseña `renz123`.

Servidores (nombre — host — proto):

| # | Servidor | Host | Proto |
|---|----------|------|-------|
| 1 | CLOUDFLARE OVPN SERVER (01) | test.pmtunnelteam.shop | 0 |
| 2 | CLOUDFLARE OVPN SERVER (02) | test.pmtunnelteam.shop | 0 |
| 3 | OVPN SSL-TSL SERVER (01) | 152.53.135.16 | 0 |
| 4 | STC Free New | www.stc.com.sa.pmtunnelteam.shop | 0 |
| 5 | Cloud Font Server (01) | dya6jd4qkhte7.cloudfront.net | 0 |
| 6 | VIP UDP SERVER (01) | udp.rajonvip.xyz | 2 |
| 7 | UDP TEST | fudp1.focusapps.site | 2 |
| 8 | DAYNAMIC SERVER 0-1 | v2ray.rajonvipnet.makeup | 3 |
| 9 | FASTLY SERVER 0-1 | ma-fastly.twimg.com | 3 |
| 10 | GCP SERVER 0-1 | rajonxo1-921962002558.europe-west4.run.app | 3 |
| 11 | SERVER 0-1 | rajon.rajonvip.xyz | 4 |
| 12 | VIP SERVER 01 | (vacío) | 3 |

Las networks son configs por país/operador (KSA STC/Jawwy/Mobily,
Kuwait, Bangladesh, India JIO, Pakistán, Etiopía, Angola, Uganda,
Zimbabwe…), con payloads HTTP/WS típicos (`[crlf]`, `[host]`, `[rlb]`,
`[protocol]`, `[ua]`).

## Cifrado (recuperado de `libovpn3.so`)

Cuerpo = `Base64( AES-128-CBC( XXTEA( JSON ) ) )`:

- **AES:** clave = `SHA-256(SIGN_KEY)[:16]`, IV = 16 bytes cero, PKCS#7.
  `SIGN_KEY = b"T}wcex;{(*~$4M5XZtd!zK"` (22 caracteres).
- **XXTEA:** estándar, delta `0x9E3779B9`, rondas `6 + 52//n`, clave = los
  mismos 16 bytes (truncada en el primer byte NUL, como hace el código
  nativo), última palabra = longitud del plaintext. **No hay paso "-2
  por byte"** en esta app (a diferencia de la mayoría de perfiles RENZ).
- **Campos internos:** cada string del JSON (nombres, hosts, puertos,
  payloads, SNI, usuario/contraseña) va cifrado igual:
  `Base64( AES-128-CBC( XXTEA( texto ) ) )` con la misma clave/IV.

Cómo se recuperó la clave (resumen): la clave NO está en texto plano
en el `.so`. Está en 18 strings ofuscados con `ay::obfuscated_data`
guardados como variables TLS (`__thread`) en `libovpn3.so`, con su
bytes cifrados escritos por bloques de inicialización y la máscara XOR
en `.rodata`. Se emularon los bloques de init y las funciones
`decrypt()` con Unicorn (18/18 recuperados). El string de 23 bytes
`T}wcex;{(*~$4M5XZtd!zK` es la semilla que `renz_decrypt`/`renz_encrypt`
usan como clave (SHA-256 → 16 bytes). Los demás strings descifrados son
nombres de métodos JNI (`getPackageManager`, `getApplicationInfo`,
`sourceDir`, `getPackageArchiveInfo`, `signatures`, `toCharsString`,
`getPackageName`, `equals`, `dataDir`, `/proc/self/maps`,
`org.ratunnellite.xyz`) usados por `getSignKey`/`initializeApp` para
comprobaciones anti-tamper, no para el cifrado del catálogo.

Librerías nativas (todas en `config.arm64_v8a.apk`; la base no trae
`.so`): `libdns.so`, `libgojni.so`, `libhysteria2.so`, `libmmkv.so`,
`libotensahorse.so`, `libovpn3.so` (aquí vive el cifrado RENZ),
`libpdnsd.so`, `libtun2socks.so`, `libudp.so`, `libv2raysocks.so`.

## Uso

```bash
python3 RA_Tunnel.py                 # descarga y muestra el catálogo vivo
python3 RA_Tunnel.py --json          # + vuelca el JSON descifrado
python3 RA_Tunnel.py --out out.json  # guarda el JSON descifrado
python3 RA_Tunnel.py --file body.b64 # decodifica un cuerpo guardado
python3 RA_Tunnel.py --self-test     # pruebas de respuesta conocida
```

Solo biblioteca estándar de Python (el AES-128 es implementación propia
verificada contra PyCryptodome y contra el vector FIPS-197).

## Formatos de archivo y esquemas URI

**La app no tiene formato propio de archivo ni esquema URI:**

- `RenzUtils` solo declara `decrypt`/`encrypt`/`initializeApp`/etc.;
  los nativos `readServer`/`writeServer`/`readPayload`/`writePayload`
  existen en `libovpn3.so` pero **no están declarados ni se usan** en
  esta app (código muerto de la librería compartida RENZ).
- El manifiesto no define ningún `intent-filter` con esquema ni acción
  VIEW.
- La app importa archivos genéricos `.ovpn`/`.conf` (OpenVPN, ya cubierto
  por SP-DECODE) y construye enlaces estándar `vless://` / `vmess://`
  internamente (también ya cubiertos).

Por eso **no hay `RA_Tunnel_archivos.py`**.

## Pendientes

- Ninguno para el catálogo: descarga, descifrado y conteo verificados
  en vivo dos veces (2026-11-14). Si el servidor rota la clave o la URL,
  el script fallará con `ValueError` (no inventa datos) y habrá que
  re-analizar `libovpn3.so`.
- Muestra real: un archivo exportado por la app (si la app llega a
  exportar alguno) serviría para confirmar que no hay formato propio
  oculto; por ahora no hay evidencia de ninguno.
