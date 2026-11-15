# Zam VIP NET / Free VIP Net — SP-DECODE

App: **zam.freevipnet.com 42.0** (build 42, minSdk 24), familia RENZ
(`renz.javacodez.vpn.*`). XAPK de APKPure, variante **arm64-v8a**
(SHA-256 de disco `8310534f…`; el SHA publicado por APKPure `6dd6a81d…`
corresponde a la variante armeabi-v7a por defecto, no a esta; la identidad
está confirmada por el manifest). Sin cobertura previa en el repo
SP-DECODE (rama `feat/nuevas-integraciones`, re-clonado 2026-11-14).

## Catálogo en vivo (verificado 2026-11-14)

- **URL:** `GET https://www.zamscript.xyz/api/json/l160D7cKZ9XXUQTJMjnpZKNp5QvVBMEC0GRihMCQBr2mSPNBrkvWMv547qVefd5F`
  (Volley `StringRequest`; la app lo pide solo si existe
  `/META-INF/KEY0.RSA` o `/META-INF/BNDLTOOL.RSA` en el APK).
  Respuesta: una sola línea Base64 (927.168 caracteres).
  El cuerpo es idéntico con UA curl y con UA Dalvik de la app.
- **Versión del catálogo: 2.458** — Notes: "Please Updete Config Version latest"
- **113 servidores, 591 redes (networks)**, usuario/clave `zambro1` / `zambro1`
- Redes con Payload: 276 · con SNIHost: 239 · servidores V2Ray: 37 ·
  servidores SlowDNS: 5 · servidores con certificado personalizado: 40
- Países (campo `flag`): fr 37, de 26, sg 9, in 8, sa 7, gb 4, us 3, ca 3,
  au 2, nl 2, om 2, ir 2, jm 2, ma 2, kw 1, qa 1, af 1, ug 1
- **Todos los campos descifran: 0 campos indescifrables** en la última
  descarga en vivo (113 servidores + 591 redes completos).

## Esquema (libovpn3.so, `RenzUtils.decrypt`, 3 modos)

Material en `.rodata` de `libovpn3.so` (config.arm64_v8a):
seed 32 B @0x27fda8, salt fijo 32 B @0x27fd88/0x27fe14, IV 16 B @0x27fdc8.

| Modo | Uso | Pipeline |
|---|---|---|
| 0 | catálogo y la mayoría de campos | Base64 → AES-128-CBC (key = SHA-256(seed)[:16], IV fijo) → XXTEA (delta `0x85A92C1F`, sumas negadas, última palabra = longitud) |
| 1 | ServerIPHost, SNIHost, Payload, V2Ray.PATH/V2RayHost, CustomV2RAYConfig | Base64 → Threefish-256 por bloques de 32 B (tweak = (nº bloque, 192·nº bloque), key = HKDF-SHA256 32 B: salt = FIXED_SALT, IKM = seed, info = "") → quitar NULs finales → AES-128-CBC (key = HKDF-SHA256 16 B con salt = FIXED_SALT[:16], mismo IV) |
| 2 | Username / Password | Caracteres invisibles ZWSP(U+200B)=0 / ZWNJ(U+200C)=1 (ZWJ U+200D se ignora); 8 tokens → 1 byte, intercambio de bits adyacentes, XOR 0x5A → XXTEA (key = PBKDF2-HMAC-SHA256(seed, FIXED_SALT, 100000)[:16]) → AES-256-CBC (key = PBKDF2 32 B, IV = primeros 16 B de la salida XXTEA) |

Notas de reversing:
- El XXTEA de Zam **no** usa el delta estándar `0x9E3779B9` (RA Tunnel sí):
  delta `0x85A92C1F`; el descifrado empieza en `-(rondas·delta)` y suma
  delta en cada ronda (equivale a cifrar con delta `0x7A56D3E1`).
- El modo 0 se verificó por re-cifrado: re-cifrar el plaintext del catálogo
  en vivo reproduce el cuerpo original **byte a byte** (927.168 caracteres).
- Caso borde del modo 1: si el cifrado AES termina en `0x00`, el strip de
  NULs del código nativo se come un byte real del cifrado (la propia app
  tampoco abre esos campos). El script repone ceros hasta el siguiente
  múltiplo de 16 y el padding PKCS#7 valida el resultado. Casos reales:
  ServerIPHost `luqman3-542877267152.europe-west3.run.app` (el servidor
  rotó de `luqman2` a `luqman3` entre dos descargas) y SNIHost `scu.eg`.
- Las 41 cadenas TLS ofuscadas de libovpn3.so son solo nombres anti-tamper
  (getPackageManager, signatures, /proc/self/maps, …); la semilla real es
  el material `.rodata` de arriba, no una SIGN_KEY como en RA Tunnel.
- Los strings de la app son LSParanoid "Muddy" (`Ljn;->a(J)`); el
  desofuscador `paranoid-deobfuscator` falló (IndexError/MemoryError) y
  jadx murió al 45%: se usó baksmali + un port Python del resolver.

## Archivos propios

- **`.zvn`** — texto `zamvipnet://<cifrado modo 0>` (ACTION_VIEW en el
  manifest, `pathPattern .*\.zvn`; `ZamVIPNETMain.c0` → `O` comprueba el
  prefijo, lo quita y descifra con `gf1.b` = modo 0). El JSON puede traer
  `isSetExpiry` / `Expiry` / `isPinEnabled`, o ser un catálogo completo.
- **`.js` / `.rj`** — importación por selector de archivos: el contenido es
  el cifrado modo 0 directamente, sin prefijo.
- **Esquema de texto: `zamvipnet://<cifrado>`** — definido y funcional
  (mismo handler que `.zvn`).
- La app guarda la config importada dentro de un zip `a.rlb` en getFilesDir()
  (antes quita `classes.dex`); la exportación escribe el JSON en claro.

## Entregables

- `Zam_VIP_NET.py` (SHA-256 `68591b5508a1144edda4968c309d1e5a9d0e008c59e67d2b18ff7b5fd9eccc1f`) —
  stdlib puro; `decode()` + `run()` + CLI `--url/--out/--raw-out/--body/--self-test`.
  Verificado: `--self-test` TODO OK (14 checks: AES-128/256 FIPS-197,
  XXTEA, Threefish, round-trips de los 3 modos y vectores reales);
  `--url` en vivo OK (2.458, 113/591, 0 campos indescifrables).
- `Zam_VIP_NET_archivos.py` (SHA-256 `e3080bc3d8931ed5c04531796c84edb29955321b9137dc8b9a3ea79c2aec21d7`) —
  decodificador `.zvn` / `.js` / `.rj` / `zamvipnet://` / JSON en claro.
  Verificado: `--self-test` OK y archivos `.zvn` y `.js` sintéticos abren.
- `Zam_VIP_NET.png` 512×512 (SHA-256 `50f6850f76f0943972860fc8d4905c16ce5f5562c26ca92f08e8c967dbceddb0`,
  icon.png del XAPK).

Pendiente: un `.zvn` real exportado por la app en un teléfono para confirmar
el decodificador de archivos extremo a extremo (hoy solo round-trip contra
el método verificado en la librería y archivos sintéticos).

Trabajo en `work/`: `apk/` extraído (base + splits), `smali/` (baksmali),
`deob_renz.txt`, `resolve_jn.py`, `catalog_live_body.txt`,
`catalog_live_decrypted.json`, `catalog_live_readable.json`,
`mode1.py`, `mode2.py`, `mode0_enc.py`, `tally_all.py`, `decode_full.py`,
`obf_plain.json` (41 cadenas TLS), `manifest2.txt`.
