# Rev Hunter — com.hunter.net (version 48)

Decodificador de catálogo y de archivos de configuración para SP-DECODE.
App brasileña (UI en portugués), 32 bits (armeabi-v7a solamente), protegida
con LIAPP v5.1.1.183. Sin cobertura previa en el repo.

## Catálogo

- **Endpoint (petición exacta de la app):**
  `GET https://update.revhuntervpn.com/cache/48` — GET plano, sin
  cabeceras propias ni autenticación. El servidor no filtra User-Agent.
  `[version]` en `LinkUpdate` es el **versionCode de la app ("48")**, no la
  `Version` del catálogo ("1.3.2"): `/cache/1.0.0` y `/cache/[version]`
  devuelven 404.
- **Formato TSH1** (descifrador `w23.o`, `classes11.dex`, + nativo
  `libwoldk.so`):
  Base64 → Base91 (alfabeto basE91) → sobre `TSH1`
  (`magic` | `salt[16]` | `nonce[12]` | `ct_len` LE32 | `crc64` LE64 | `ct`).
  Clave: PBKDF2-HmacSHA1(contraseña de formato `"ChupaMeuPiru"`, salt,
  100 iteraciones, 256 bytes). CRC-64 reflejado (polinomio de
  `K[192:200]` LE64 con bits 63 y 0 a 1; init `0xFFFFFFFFFFFFFFFF`;
  final `~crc`) sobre `salt || nonce || ct` — verificado en asset y en vivo.
  Capas sobre el `ct` (orden de descifrado):
  1. ChaCha con **1 doble ronda** (8 quarter-rounds), clave `K[0:32]`,
     nonce de 12 B, contador desde 1.
  2. S-box xoshiro256**: 8 tablas inversas (una por posición de byte
     mod 8), semilla `K[64:96]` como 4 LE uint64.
  3. RC4 con clave `K[0:32]`, descartando los primeros 1536 bytes.
  4. Rotación de nibbles con clave `K[128:192]`.
  5. `dk.d` nativo (`libwoldk.so`, `Java_com_hunter_net_a_dk_d`):
     Fisher-Yates con PRNG java.util.Random (LCG `0x5DEECE66D`) sembrado
     por `SHA-256("MamaX9Safadinho$$$$$$" || 16 ceros || "SHUF")`,
     scatter, **reversión de bytes** y XOR con bloques
     `SHA-256(semilla || LE32(bloque))` donde
     `semilla = SHA-256("MamaX9Safadinho$$$$$$" || "XOR:" || 16 ceros)`.
     Reimplementado en Python puro (verificado byte a byte contra el
     nativo emulado con Unicorn en 17 longitudes × 2, incluida 14265).
  6. GZIP → JSON UTF-8.
- **Prueba en vivo (2026-11-13):** `GET .../cache/48` → HTTP 200,
  23,464 B. Descifra a **Version 1.3.2, AppVersion 48, 56 servidores
  (47 BR, 8 US, 1 aleatorio; sin distinción premium — todos libres),
  88 Networks (payloads, 81 con Payload), 9 NetworksAuto**,
  TimeUpdate 10, ReleaseNotes null. El asset incluido en el APK
  (`assets/config/config.json`) abre igual: Version 1.0.0, 56 servidores,
  87 Networks.
- Uso: `Hunter_VPN.py --url` (o `--url 48`, o una URL completa) /
  `Hunter_VPN.py <archivo>`. `--self-test` hace round-trip TSH1 completo
  (cifrado inverso incluido) y vector conocido de `dk.d`, sin red.

## Archivos de configuración

- **`.rev`** (manifest: VIEW, schemes `content`/`file`,
  `pathPattern .*\.rev`): el mismo sobre TSH1 que el catálogo. La app
  solo lo acepta si el JSON `AppVersion` es igual al versionCode (48);
  este decodificador devuelve el JSON sin imponer ese chequeo.
  `Hunter_VPN_archivos.py <archivo.rev>` lo abre (verificado contra el
  asset y contra el catálogo en vivo: salida idéntica al JSON del catálogo).
- **`.custom`** (manifest: `pathPattern .*\.custom`): Base64 → JSON.
  Campos que lee la app (`k()`): `"method"` (int 0-3) más claves de
  servidor ofuscadas por LIAPP (se devuelven tal cual), y en claro
  `"CUSTOM_AUTH"` (bool), `"USUARIO_CUSTOM"` y `"SENHA_CUSTOM"`
  (solo si `CUSTOM_AUTH` es true). Las protecciones se revisan DESPUÉS
  de descifrar; no derivan la clave.
- **Sin `.sks`**: la app no tiene soporte `.sks`.
- **Sin esquemas URI de texto**: no hay `revhunter://` ni similar; la
  app solo importa por intents `content`/`file` con `.rev`/`.custom`
  (las dos cadenas LIAPP de `onCreate` son esos schemes estándar).
  Solo los `vmess://`, `vless://`, `ss://`, `trojan://` estándar, que
  SP-DECODE ya cubre.

## Estado y pendientes

- Catálogo y archivos `.rev`/`.custom` **completados y verificados en vivo**.
- Pendiente: confirmación extremo a extremo con un `.rev` o `.custom`
  real exportado por la app en un teléfono (el formato ya está probado
  contra el asset incluido y contra el catálogo en vivo; riesgo bajo).
- Pendiente: las claves LIAPP del formato `.custom` (nombres de campo
  de servidor) no se resolvieron — requerirían reproducir el parser
  nativo SGB2 de LIAPP; el decodificador no las necesita (devuelve el
  JSON tal cual).
- Notas de trabajo y evidencia en `work/` (descompilaciones, emulador
  Unicorn de `dk.d`, blobs de asset y en vivo, JSON descifrados).
  Sección en `~/workspace/catalogs/NOTES.md`.

## Archivos

- `Hunter_VPN.py` — catálogo (decode + run + CLI `--url`).
- `Hunter_VPN_archivos.py` — archivos `.rev` / `.custom`
  (importa el descifrador TSH1 de `Hunter_VPN.py`; mantener juntos).
- `Hunter_VPN.png` — icono 512×512 del XAPK.
- `README.md` — este archivo.
