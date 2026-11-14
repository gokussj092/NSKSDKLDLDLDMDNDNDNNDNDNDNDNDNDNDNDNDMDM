# Binke Volt VPN — SP-DECODE

App: **xyz.binkevoltvpn.org 1.1** (build 11, minSdk 23), familia RENZ
(`renz.javacodez.vpn.*`). XAPK de APKPure, variante **arm64-v8a**
(SHA-256 de disco `0becd137f3901de6f292f980cfa3bf706db05992629676060c28ec181d649a83`,
coincide exacto con el publicado por APKPure). Sin cobertura previa en el
repo SP-DECODE (rama `feat/nuevas-integraciones`, re-clonado 2026-11-14,
86 apps, 0 coincidencias con binke/volt).

## Catálogo en vivo (verificado 2026-11-14)

- **URL:** `GET https://raw.githubusercontent.com/snapb/B_SHIELD/refs/heads/main/Benben_cnofig.js`
  (nótese el typo `cnofig` en el nombre real del archivo; Volley
  `StringRequest` sin cabeceras propias, UA Dalvik por defecto).
  Respuesta: una sola línea Base64 (789.081 caracteres).
- **Versión del catálogo: 13.67** — Notes: "New update available"
- **55 servidores, 789 redes (networks)**, usuario/clave `binke` / `binke`
- Redes con Payload: 410 · con SNIHost: 332
- Países (campo `flag`): fr 10, ma 6, us 6, de 6, et 6, dz 4, mr 4, gb 4,
  sa 3, ml 2, cd 1, it 1, ro 1, za 1
- Sin campo estructurado de gratis/premium (sin Category ni IsPremium);
  los nombres de servidor incluyen "SERVER GCP VIP 01–03" y
  "Google Cloud Server 01–04⚡️"
- **Todos los campos descifran: 0 campos indescifrables** en la última
  descarga en vivo (55 servidores + 789 redes completos).

## Esquema (libovpn3.so, `RenzUtils.decrypt`, 3 modos)

Material en `.rodata` de `libovpn3.so` (config.arm64_v8a):
seed 32 B @0x27f4a8, IV 16 B @0x27f4c8, FIXED_SALT 32 B @0x27f514.
JNI `decrypt` en 0x495130, `encrypt` en 0x493e8c; dispatch de modos en
0x49517c (modo 1 → decryptSpecial 0x4941a0, modo 2 → decryptSensitive
0x494988, modo 3 → decryptDex 0x494c94, resto modo 0).

| Modo | Uso | Pipeline |
|---|---|---|
| 0 | catálogo y la mayoría de campos (Name, Subname, puertos, flag, CustomCert, network Name/Info, Squid, Obfs, DNSResolver) | Base64 → AES-128-CBC (key = SHA-256(seed)[:16], IV fijo) → XXTEA (delta `0x85A92C1F`, sumas negadas, última palabra = longitud) → **restar 2 a cada byte** |
| 1 | ServerIPHost, SNIHost, Payload | Base64 → Threefish-256 por bloques de 32 B (tweak = (nº bloque, **64**·nº bloque), key = HKDF-SHA256 32 B: salt = FIXED_SALT, IKM = seed, info = "") → quitar NULs finales (con fallback) → AES-128-CBC (key = HKDF-SHA256 16 B con salt = FIXED_SALT[:16], mismo IV) |
| 2 | Username / Password (de servidor y del catálogo) | Base64 → XXTEA (key = PBKDF2-HMAC-SHA256(seed, FIXED_SALT, 100000)[:16]) → AES-256-CBC (key = PBKDF2 32 B, IV = primeros 16 B de la salida XXTEA) |

Notas de reversing:
- El XXTEA de Binke usa el mismo delta `0x85A92C1F` que Zam (no el
  estándar `0x9E3779B9` de RA Tunnel). La diferencia con Zam está en el
  modo 0 (Binke resta 2 a cada byte tras el XXTEA; Zam no), en el tweak
  del modo 1 (64·n en Binke, 192·n en Zam) y en el modo 2 (Binke usa
  Base64 directo; Zam usa caracteres invisibles).
- El modo 0 se verificó por re-cifrado: re-cifrar el plaintext del
  catálogo en vivo reproduce el cuerpo original **byte a byte**
  (789.080 caracteres).
- Caso borde del modo 1: si el cifrado AES termina en `0x00`, el strip
  de NULs del código nativo se come un byte real del cifrado (la propia
  app tampoco abre ese campo). El script prueba sin quitar NULs y
  reponiendo ceros hasta el siguiente múltiplo de 16; el padding PKCS#7
  valida el resultado. Caso real: Payload de network[592]
  ("🇦🇷🇧🇷 Argentina | Personal", 256 B, Host
  `ayudaysoporte.personal.com.ar`).
- Las 44 cadenas TLS ofuscadas de libovpn3.so son solo nombres
  anti-tamper (getPackageName, signatures, /proc/self/maps,
  `pm clear xyz.binkevoltvpn.org`, killProcess, …); la semilla real es
  material `.rodata` en claro, no una cadena TLS (igual que en Zam).
- El descifrado de esas cadenas TLS por emulación Unicorn reveló el
  método: los 12 `obfuscated_data::decrypt()` se llaman por stubs PLT,
  nunca por `bl` directo; el flag de "ya descifrado" se limpia ANTES de
  escribir los datos, así que la emulación debe usar presupuesto fijo
  de instrucciones (300), no parar en flag==0.
- Una URL de Pastebin en resources.arsc
  (`https://pastebin.com/raw/QWtWa5BM`) devuelve 404 — es una plantilla
  vieja, no el catálogo.

## Archivos propios (ver `Binke_Volt_archivos.py`)

| Formato | Contenido |
|---|---|
| `.bvv` | Texto `binkevoltvpn://<cifrado modo 0>` de un JSON de perfil (un servidor/red). Manifest: ACTION_VIEW, schemes file/content, pathPattern `.*\.bvv`, mime `*/*`. La app comprueba el prefijo, descifra en modo 0, revisa isSetExpiry / Expiry / isPinEnabled, pone Type="Imported" y guarda en `custom_payload.json` cifrado en modo 0. |
| `.js` / `.rj` | Cifrado modo 0 de un catálogo completo, sin prefijo. Selector de archivos (requestCode 1996); la app comprueba que el campo Version coincida con la versión guardada y guarda el texto cifrado en un zip `a.rlb`. |
| `binkevoltvpn://<cifrado>` | Enlace de texto, mismo formato que `.bvv`; se atiende dentro de la app (Q()/f0()), **sin** intent-filter con ese scheme en el manifest. La exportación (requestCode 1999) escribe `binkevoltvpn://%s` del perfil cifrado en modo 0. |

Sin formato `.sks`. Sin otro esquema URI propio.

## Uso

```bash
python3 Binke_Volt.py                       # descarga y resume el catálogo en vivo
python3 Binke_Volt.py --url <URL>           # otra URL de catálogo (mismo formato)
python3 Binke_Volt.py --file catalogo.b64   # descifra un cuerpo Base64 guardado
python3 Binke_Volt.py --out catalogo.json   # guarda el JSON descifrado
python3 Binke_Volt.py --self-test           # 17 comprobaciones (FIPS, round-trips, vectores reales)
python3 Binke_Volt_archivos.py perfil.bvv   # descifra un .bvv / .js / .rj
python3 Binke_Volt_archivos.py --self-test  # 6 comprobaciones (incl. el catálogo vivo como .js real)
```

Solo stdlib. El `--url` en vivo tarda ~1 min (Threefish/AES en Python puro
sobre 789 KB + ~3.900 campos).

## Archivos

- `Binke_Volt.py` — decodificador del catálogo (`decode()` + `run()` + CLI)
- `Binke_Volt_archivos.py` — decodificador de `.bvv` / `.js` / `.rj` y
  `binkevoltvpn://`
- `Binke_Volt.png` — icono 512×512 (del `icon.png` 240×240 del XAPK)
- `catalog_sample.b64` — cuerpo Base64 del catálogo en vivo (2026-11-14)
- `catalog_sample.json` — mismo catálogo ya descifrado (Version 13.67)

## Pendiente

- Un `.bvv` / `.js` / `.rj` real exportado desde el teléfono, o un enlace
  `binkevoltvpn://` real, para validar el formato de perfil de un solo
  servidor (el formato de catálogo completo ya está validado con el
  catálogo en vivo).
