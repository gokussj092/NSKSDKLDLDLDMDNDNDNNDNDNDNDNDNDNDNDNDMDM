# OSP Tunnel — decodificador de catálogo para SP-DECODE

App: **OSP Tunnel** (`xyz.osptunnel.org`) **3.7, build 37** — XAPK APKPure
variante arm64-v8a (52.301.385 B; SHA-1 `806c739ab5da1e992d01e9ccd91429fe9e4c59dd`
coincide con el File SHA1 publicado por APKPure para esta variante;
el SHA-256 `bcec4d77…` de la página es de la variante armeabi-v7a).
Versión de Google Play verificada el 2026-11-13 (actualizada 30 sep 2026).

Familia **RENZ / 7NET** (`renz.javacodez.vpn.*`, `libovpn3.so`).
El repo SP-DECODE ya cubre la familia en `decoders/Python/renz.py`
(`.osp` y `osp://`/`osptunnel://` → perfil `"7net"`), pero no tiene
carpeta propia para OSP Tunnel: este es el catálogo específico de la app.

## Catálogo en vivo

```
GET https://raw.githubusercontent.com/MAKE-MONEY-MILLION-DOLLAR-PER-DAY/7net-Team/refs/heads/main/7net%2BAll_Team.js
```

Petición de la app: Volley `StringRequest`, GET simple, sin cabeceras
ni autenticación (UA Dalvik de Android). Respuesta: una sola línea
Base64 (774.144 caracteres el 2026-11-14, SHA-256
`40e5cdf9052e8d68b568168a95e1c7c1fde32c85e05e7d8077ee4270a6e48ef6`).

- **Versión del catálogo: 40.71**
- **81 servidores, 621 redes (networks)**
- Redes con Payload: **485**; redes con SNIHost: **467**
- Servidores V2Ray: 26; servidores SlowDNS: 3; servidores con
  CustomCert (config OpenVPN): 40
- Usuario/clave del catálogo: `ksksksk` / `kslsllsm`
- **Sin distinción gratis/premium en los datos**: no hay campo
  `IsPremium` ni `Category` en servidores ni redes.
- Campos descifrados: **4.794 / 4.794 (0 sin descifrar)**.
  Notas: texto en árabe (alerta de Google Cloud Run "Always-on Mode").

## Esquema (libovpn3.so, `RenzUtils.decrypt`, 3 modos)

Constantes `.rodata` (verificadas contra el catálogo vivo):

| Material | Valor |
|---|---|
| seed (32 B, @0x27eb08) | `deb72221be4652c347f930e85adc29970ccd499cf42e361b3d6b14918912bf3b` |
| salt fijo (32 B, @0x27eb74) | `70ed508428ff7b5bcde0bcdd3b9474932ab1cabc5ff6870e6e584b4fa7925f55` |
| IV (16 B, @0x27eb28) | `2d2f3112a271edbba9a41ad58a3a99bf` |
| key modo 0 | `SHA-256(seed)[:16]` = `c42960423d85942052ae1d275cc71f67` |
| key modo 2 (PBKDF2) | `PBKDF2-HMAC-SHA256(seed, salt, 100000, 32)` = `94e2ef70fa549d54bc830ab6297cf958c51b45ec42fff58c5fdb5541040fe503` |
| key modo 1 AES | `HKDF-SHA256(salt[:16], seed, "", 16)` = `e50acb6fd8d056b159bbf414c4acd908` |
| key modo 1 Threefish | `HKDF-SHA256(salt, seed, "", 32)` = `a8fe4b23f5ad67851d981cca6522d6b2f2bdca67e739751c3b5ad68552fb8311` |

- **Modo 0** (catálogo y la mayoría de campos): Base64 → AES-128-CBC
  (key = SHA-256(seed)[:16], IV fijo, PKCS#7) → XXTEA
  (delta `0x7a56d3e1`, última palabra = longitud) → cada byte − 2.
- **Modo 1** (`ServerIPHost`, `SNIHost`, `Payload`, `V2Ray.PATH`,
  `V2RayHost`, `V2Ray.CustomV2RAYConfig`): Base64 → Threefish-256 por
  bloques de 32 B (**tweak = (n_bloque, 0)** — distinto de Zam, que usa
  (n, 192·n); key = HKDF de 32 B) → quitar NULs finales → AES-128-CBC
  (key = HKDF de 16 B, mismo IV, PKCS#7).
- **Modo 2** (`Username`, `Password`): Base64 → XXTEA
  (key = PBKDF2[:16]) → AES-256-CBC (key = PBKDF2 de 32 B,
  IV = primeros 16 B de la salida XXTEA, PKCS#7).

**Caso borde del modo 1 (6 campos):** si el cifrado AES termina en
`0x00`, el strip de NULs del código nativo se come un byte real y la
longitud deja de ser múltiplo de 16 (la app tampoco abre esos campos).
El script repone ceros hasta el siguiente múltiplo de 16 y el padding
PKCS#7 valida el resultado. Ejemplos reales: Payload de la red 95
(`GET wss://[rlb]…`) y SNIHost de la red 496 (`com.telegram.org`).

**Nota de seguridad:** `getSignKey` (0x3b4100) es anti-tamper: lee la
firma del propio APK (PackageManager → signatures → hex DER) y
`RenzUtils.decrypt` no funciona sin inicializar la app. La clave del
catálogo NO depende de esa firma: las constantes de arriba son fijas
en `.rodata` y el catálogo vivo se descifra con ellas sin el APK.

## Archivos y enlaces propios

- **`.osp`** — texto con el cifrado (modo 0, o 1/2) de un JSON; acepta
  `osptunnel://<cifrado>`, el alias `osp://<cifrado>`, el cifrado
  directo sin prefijo, o JSON en claro. El JSON puede traer
  `isSetExpiry` / `Expiry` / `isPinEnabled` / `NetworkPinCode`
  (config compartida) o ser un catálogo completo.
- **`osptunnel://<cifrado>`** — enlace de texto, mismo formato. La app
  lo valida (`"Error! format must start osptunnel://"`) y lee los
  campos de expiración/PIN. No hay intent-filter de esquema ni de
  extensión en el manifest: la importación es por pegado de enlace.
- Validado: un `.osp` y un `osptunnel://` sintéticos (construidos con
  este script) los abre también el `decoders/Python/renz.py` del repo.

## Uso

```bash
python3 OSP_Tunnel.py --self-test
python3 OSP_Tunnel.py --url https://raw.githubusercontent.com/MAKE-MONEY-MILLION-DOLLAR-PER-DAY/7net-Team/refs/heads/main/7net%2BAll_Team.js --out catalogo.json
python3 OSP_Tunnel.py --body cuerpo_guardado.txt --out catalogo.json
python3 OSP_Tunnel_archivos.py archivo.osp [--out config.json]
python3 OSP_Tunnel_archivos.py "osptunnel://<cifrado>"
python3 OSP_Tunnel_archivos.py --self-test
```

Solo stdlib (AES, XXTEA, Threefish-256, HKDF y PBKDF2 implementados
en Python puro). `--self-test` verifica los cifrados con vectores
reales del catálogo vivo 2026-11-14 (18 comprobaciones).

## Pendiente

- Un archivo `.osp` real exportado desde la app y un enlace
  `osptunnel://` real, para confirmar el formato de exportación
  (el formato aquí documentado es el que acepta la importación
  según el código de la app y el `renz.py` del repo).
