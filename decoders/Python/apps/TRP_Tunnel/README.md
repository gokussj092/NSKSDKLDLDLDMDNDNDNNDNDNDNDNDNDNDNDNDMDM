# TRP Tunnel 1.0.9 (com.trptunnel.xyz, build 109)

Decodificador del catálogo en vivo de TRP Tunnel para SP-DECODE.
Tanda 10c, 2026-11-14. Python stdlib puro, sin dependencias.

## App

- Paquete: `com.trptunnel.xyz`, versión 1.0.9, build 109, minSdk 23, targetSdk 35.
- XAPK arm64-v8a de APKPure (versión de Google Play verificada 2026-11-13):
  `browser-download-20261114T063424.534434596Z-0-TRP_Tunnel_1.0.9_APKPure.xapk`
  (46,790,250 B, SHA-256 `f9a702e10d6a24b2c21dd29a5343805c7e545d5e5dbe5ad8f037cf07f71441a8`;
  SHA-1 `6acb89305baf4e08e7c6fed86b97e66c7824f0f3` = File SHA1 publicado por
  APKPure para esta variante arm64).
- Familia RENZ: paquete Java `renz.javacodez.vpn`, `libovpn3.so` construido
  por "renz-ubuntu" desde xray-core, `https://t.me/PHRenzOrigin` en el
  binario. Actividad principal `TrinetRebornPlusMain` (fork Trinet Reborn
  Plus / IPHunter).
- Repo SP-DECODE: **sin cobertura previa** (ni carpeta ni perfil trptunnel
  en `decoders/Python/apps/` ni en `decoders.json`; repo re-clonado sparse,
  rama `feat/nuevas-integraciones`, 86 carpetas).
- Librerías nativas: TODAS en `config.arm64_v8a.apk` (la base NO trae .so):
  `libdns.so`, `libgojni.so`, `libhysteria2.so`, `libmmkv.so`,
  `libogkayouy.so` (24 MB), `libovpn3.so` (7,053,744 B, aquí vive el
  cifrado RENZ), `libpdnsd.so`, `libtun2socks.so`, `libv2raysocks.so`.

## Catálogo en vivo

URL exacta (encontrada en `TrinetRebornPlusMain.L()`, llave LSParanoid
`-0x6c2680c550d4L`):

    https://raw.githubusercontent.com/Jcacanog12/trinet-pro-reborn-auto/refs/heads/main/Trinetv5

Petición exacta de la app: Volley `StringRequest` GET, sin cabeceras, sin
cuerpo, sin User-Agent (Volley no envía UA por defecto). El host
(`raw.githubusercontent.com`) responde 200 a cualquier UA. Respuesta: una
línea larga de Base64 (234,205 B, SHA-256
`29ce87c4dfe8aff4ff8391607b488317f890e100655ec2a65c25bb27447d2544`).

Flujo en la app (`La71.onResponse`): `sb1.l(body)` valida el cuerpo →
`xb1.a(context, body)` = `new String(RenzUtils.decrypt(...))` → parsea el
JSON → compara su `Version` con la guardada; si es igual procesa/guarda
el catálogo (`TrinetRebornPlusMain.J`), si no, muestra un diálogo
"No Update".

## Cifrado (RENZ, recuperado de libovpn3.so)

    Body = Base64( XXTEA( AES-128-CBC( JSON ) ) )

**OJO con el orden de capas: XXTEA por FUERA, AES por DENTRO** — al revés
que RA Tunnel (AES fuera, XXTEA dentro). Ambas capas usan la misma clave:

- Semilla: `Lz(?+Z!j9.p$F@N>` (17 caracteres), recuperada del string
  ofuscado TLS `ay::obfuscated_data<17>` en `libovpn3.so` (objeto
  `0x6bc370`, llamado desde `renz_decrypt` en `0x3a491c`). Es la semilla
  fija de la app, NO el certificado de firma del APK.
- Clave AES = SHA-256(semilla)[:16] = `91f9eea7eb614fbbff2521e76306cea4`;
  IV = 16 bytes cero, PKCS#7.
- XXTEA = XXTEA estándar, delta `0x9E3779B9`, rondas `6 + 52//n`, clave =
  la misma de 16 bytes (truncada en el primer NUL, como el código nativo),
  última palabra = longitud del plaintext.
- Cada campo string del JSON (nombres, hosts, puertos, payloads, SNI,
  TLSVersion, los valores anidados de `UDPOptions` / `ProxySettings`,
  `Username` / `Password` de nivel superior) se cifra igual:
  `Base64( XXTEA( AES-128-CBC( plaintext ) ) )`.

Verificación: la dirección de cifrado se verificó byte por byte —
re-cifrar el plaintext en vivo reproduce el cuerpo en vivo exactamente
(`live round-trip identical: True`). El vector de campo
`HE7aegxPrqLDPhKGvpnaThiDnBbI6Esv/AdexpMsBRL8gd7i` descifra a
`UDP Hysteria Server 1️⃣`, el Name del servidor 1 en vivo.

Método de recuperación: los strings LSParanoid se resolvieron con un
puerto del algoritmo verificado de TRM (`work/resolve_zl.py`, 1,529 call
sites); las 11 plantillas `ay::obfuscated_data<...>::decrypt()` se
emularon con Unicorn (`work/emu_init_trp.py`, `work/emu_decrypt_trp.py`,
30 de 32 objetos; los 2 restantes son blobs de 1,823 y 2,841 bytes
copiados con memcpy, no la semilla). La función `renz_decrypt`
(`0x3a45a8`) y `Java_RenzUtils_decrypt` (`0x3a3f38`) se desensamblaron para
confirmar el orden de capas y la derivación de clave/IV.

## Catálogo en vivo (2026-11-14)

- **Versión: 1.2.322**
- **Servidores: 14** — 1 UDP Hysteria, 1 V2Ray normal, 1 SlowDNS, 1 Workers
  v2ray, 2 OVPN Global, 6 CloudFront, 2 Google Cloud. Protocolos: 0 = OVPN
  (9), 2 = UDP/Hysteria (1), 4 = V2Ray (4), 5 = SlowDNS (1).
- **Networks: 222** — 134 con Payload, 77 con SNIHost.
- SSLNetworks: 0.
- No hay marcador gratis/premium en los datos (todos los Subname dicen
  "Premium Server 🌍", "Premium V2RAY" o "TRP Tunnel 🌍"), así que
  gratis/premium no se puede distinguir — igual que RA Tunnel.
- `Username` en vivo: `jcacanog12` (credencial compartida del catálogo).
- `Notes`: "NEW UPDATE ⚠️ Please support us by sharing our app in your
  Telegram Channel and Group…" (pide compartir y ver anuncios).

## Formatos de archivo / esquemas URI: NINGUNO propio

- El manifest NO tiene ningún intent-filter VIEW con scheme ni asociación
  de tipo de archivo. La app no exporta archivos de configuración propios
  ni tiene esquema URI propio (`trp://` no existe).
- Guarda el catálogo internamente y genera enlaces estándar `vless://` /
  `vmess://` (plantillas en `Lsg`), ya cubiertos por SP-DECODE.
- Por eso NO hay `TRP_Tunnel_archivos.py`. `TRP_Tunnel.py --file` abre
  tanto un cuerpo crudo del catálogo (Base64) como un JSON ya descifrado
  (p. ej. el `config.json` interno de la app).

## Uso

    python3 TRP_Tunnel.py                  # descarga y descifra en vivo
    python3 TRP_Tunnel.py --url <URL>      # otra URL de catálogo
    python3 TRP_Tunnel.py --file body.b64  # cuerpo crudo guardado
    python3 TRP_Tunnel.py --file config.json  # JSON ya descifrado
    python3 TRP_Tunnel.py --self-test      # pruebas de respuesta conocida
    python3 TRP_Tunnel.py --out out.json   # guarda el JSON descifrado
    python3 TRP_Tunnel.py --json           # imprime el JSON descifrado

El resumen NO imprime credenciales (ni `Username`/`Password`).

## Entregables

- `TRP_Tunnel.py` — SHA-256
  `94d108ba9d59e5435c209e0999807021b7b37f904488be5a38c8505e06850890`
  (`--self-test` OK; `--url` en vivo OK: v1.2.322, 14/222).
- `TRP_Tunnel.png` — 512×512 RGBA, SHA-256
  `c2ca4b038810b0a1c9a7f61e2e1cd3784dabab54b6389bb1eb29c0fab0e7d038`
  (icono del XAPK, ya era 512×512).
- `catalog_sample.b64` — cuerpo en vivo 2026-11-14 (234,205 B, SHA-256
  `29ce87c4dfe8aff4ff8391607b488317f890e100655ec2a65c25bb27447d2544`).
- `work/` — scripts de análisis (resolve_zl.py, plt_map.py,
  find_init_blocks_trp.py, emu_init_trp.py, emu_decrypt_trp.py,
  try_seed3.py, try_fields.py, stats.py, make_vector.py),
  `catalog_live.b64`, `catalog_decoded.json`, `deob_strings.txt`,
  `obf_enc.json`, `obf_plain.json`, `obf_pairs.json`, `obf_call.json`,
  `plt_map.json`, `smali/`, `jadx-out/` (parcial, 63%).

## Pendiente

Nada para el catálogo. Sin muestra de archivo real que validar (la app no
tiene formato propio). Si el servidor rota la semilla o cambia la URL, el
script fallará con `XXTEA layer failed` / `AES layer failed` y habrá que
re-extraer la semilla de la nueva versión de `libovpn3.so` con el mismo
método (`work/emu_decrypt_trp.py`).
