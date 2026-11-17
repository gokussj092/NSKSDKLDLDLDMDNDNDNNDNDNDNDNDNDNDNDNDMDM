# Fx Tunnel 4.8 — ANALYSIS

- Paquete: `com.fx.tunnel` · versionCode: 39 · versionName: `4.8`
- Observado: 2026-11-17 · Estado del expediente: **PARTIAL**
  (catálogo empaquetado verificado; en vivo sin URL)
- Muestra: `Fx_Tunnel_4.8_3_5n8f.apks` (39.701.734 B, SHA-256
  `c6c5ef8c2f759499435182a9eb762ba1cec67a55182f50f5b2e08e9561b2c291`;
  base.apk + splits arm64/es/xhdpi). El .apks no se guarda en Git.

## Objetivo

Documentar el método de descifrado del catálogo empaquetado y de los
archivos `.fxt` de esta app para SP-DECODE, con evidencia
reproducible y sin secretos, como paso previo a su integración.

## Cómo se obtuvo la muestra

APK público (.apks) verificado por SHA-256 según README de origen.
Decompilación jadx 1.5.3 (con 55 errores; la clase `OpenVPNClient` no
se decompiló porque no existe en el DEX); cadenas LSParanoid
recuperadas del bytecode DEX con el mismo algoritmo que HX/TRM Tunnel;
`libputils.so` desensamblada con Capstone.

## Método del catálogo

Formato: `assets/gremlin.json` (665.036 B) es Base64 → XXTEA (delta
`0x9E5729B1`, palabras little-endian, longitud original en la última
palabra) → JSON UTF-8. La clase XXTEA es `AbstractC1765nm` (`nm`) en
`classes2.dex`; su clave `a` es la cadena LSParanoid
`-4663933677235715084`. La clave es propia de Fx: con la clave de las
apps hermanas (`Princie!`) el asset falla con longitud interna XXTEA
inválida; con la clave de Fx abre.

Handler de actualización `C1885pI.d` (`pI`, en `classes2.dex`):
`replace(" ", "").replace("\n", "")` sobre la respuesta, luego
`nm.c(respuesta, nm.a)`. Si `"Version"` es igual a la local: `"No
Update Available!"`; si es mayor, conserva los `"Payloads"` locales
cuyo `"message"` empiece por `"Custom Tweak"`, fusiona los
`"Payloads"` remotos por `"friendly_name"` (insensible a mayúsculas,
sin duplicar) y reescribe `filesDir/gremlin.json` cifrado con `DY.m` =
`nm.e` (XXTEA + Base64), mostrando `"Update Success!"`.

Lectura local: `filesDir/gremlin.json` si existe, si no el asset,
descifrado con `nm.c`. El formato **no tiene MAC**; la validación
estructural no equivale a autenticación criptográfica.

## Catálogo empaquetado (descifrado y verificado)

| Fuente | Versión | Free | Premium | Vip | Private | Payloads |
|---|---|---|---|---|---|---|
| `assets/gremlin.json` del APK (`--apks`) | **10288** | **29** | 0 | 0 | 0 | **1353** |

Secciones: `Premium_servers`, `Vip_servers`, `Private_servers`,
`Username`, `Password`, `Free_servers`, `Payloads`, `Version`,
`Changelogs`. Campos de cada servidor libre (9 claves): `category`,
`custom_cert`, `password`, `server_host`, `server_name`,
`server_port`, `server_udp_port`, `ssl_port`, `username`. Campos de
cada payload (11 claves): `category`, `dothost`, `friendly_name`,
`host`, `message`, `method`, `payload`, `port`, `query`, `sausage`,
`sslws`. El JSON de resultado (`bundled.json`) contiene solo los
datos del catálogo, todo descifrado; no incluye ninguna API de
descarga.

## Catálogo en vivo — URL NO RECUPERADA (fallo honesto)

1. La clase `rased.vpn.app.activities.OpenVPNClient` (donde vive el
   updater en las apps hermanas, p. ej. `OpenVPNClient.z()` en TRM)
   **no está definida en ninguno de los tres DEX**: `classes.dex`
   (12.532 clases), `classes2.dex` (2.540) y `classes3.dex` (26) solo
   contienen referencias a ella. Tampoco están `OpenVPNApplication`,
   `ImportTweakActivity`, `FileDialog`, `AboutActivity`,
   `AppListActivity` ni `IPHunterActivity`.
2. La capa UI está protegida por **LIAPP v5.1.1.190**
   (`assets/LIAPP.ini`, Job-Id# 134875) y se carga en tiempo de
   ejecución: `libvavawc.so` referencia `libliapp.so`/`JNI_OnLoad` y
   `assets/.vavawc.dex` es un stub de 1 clase con un método vacío.
3. Se recuperaron **961 cadenas LSParanoid** de `classes.dex`
   (287/287 llamadas `getString`) y `classes2.dex` (674/686; las 12
   restantes son claves de `SharedPreferences`, sin URL). Ninguna es
   una URL de updater: las únicas `https` son la lista de servidores
   Psiphon (`s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/
   server_list_compressed`) y `https://t.me/fxtunnelvpnupdate`
   (canal de Telegram, usado por el menú "Checking Updates").
4. `resources.arsc` y las cadenas planas de los tres DEX tampoco
   contienen ningún dominio `.store` / `.xyz` / `relay` / `updater`.
5. El listener de actualización sí existe (`C1885pI`), así que el
   flujo existe en la app; solo su disparador y su URL están en el
   código protegido.

**No se inventó ninguna URL ni se probó ninguna sustituta.** Las URLs
de las hermanas (TRM `trmrelay.store/updater/…`, HX
`ctxrelay.online/updater/…`, Handsome/RJC en
`raw.githubusercontent.com/pipoyrichards/…`) son solo referencia de la
familia. En cuanto se conozca la URL (p. ej. capturada en un teléfono
con la app instalada), `Fx_Tunnel.py --url <URL> --summary` la
descargará y descifrará con la clave ya verificada.

## Archivos .fxt — flujo y clave verificados contra la libputils.so propia de Fx

Formato: texto hexadecimal (una línea) → XOR repetido (clave de 12
bytes) → UTF-8 modificado JNI (CESU-8) → JSON
(`JSONObject.toString()` en exportación). Sin salt, IV, MAC ni firma.

Importación — `ImportTweakActivity` (VIEW, `content`/`file`, mimeType
`*/*`, pathPattern `.*\.fxt`) reenvía a `OpenVPNClient`:
`ContentResolver.openInputStream(Uri)` → `BufferedReader.readLine()`
→ `PUtils.pDecrypt(context, línea)` → `new JSONObject()`. Si
`tweak_password` no está vacío → diálogo `"Password Lock"`; si está
vacío → importación directa. Si falla: `"Invalid or Corrupted
File!"`.

Exportación — `OpenVPNClient.X(String, JSONObject)`:
`JSONObject.toString()` → `PUtils.pEncrypt(context, json)` → diálogo
`"SAVE TWEAK?"`. El sufijo es `.fxt` (manifiesto).

Políticas (se verifican DESPUÉS de descifrar; no derivan la clave):
`tweak_expiry` formato `yyyy-MM-dd-HH-mm`, `hwid_lock`,
`block_rooted`. Si todo pasa, `friendly_name` se de-duplica
(`" (n)"`) y el perfil se guarda en `gremlin.json` (array `Payloads`,
`"Imported File Successfully!"`). El lector entregado recupera todos
los campos sin ejecutar las políticas. Los nombres de campo están
confirmados como cadenas LSParanoid de ESTE APK (`tweak_password` ×5,
`friendly_name` ×15, `tweak_expiry` ×5, `hwid_lock` ×5,
`block_rooted` ×5, `Payloads` ×8, `Custom Tweak` ×12).

**Clave verificada contra la libputils.so propia de Fx
(2026-11-17).** Split `split_config.arm64_v8a.apk`,
`lib/arm64-v8a/libputils.so` (3.206.200 B, SHA-256
`e3e8d9e06dee7e98775ffd76c0bac438e2e6d5e1bb6be2e78f1157ebd501c758`):
`xorWithKey` @0x1496d4 carga la clave de 12 bytes desde `.rodata`
0xc53a6 (primeros 8 bytes con `LDR` en 0x149768, últimos 4 como
inmediatos `MOV w28, #0x6b66` + `MOVK w28, #0x5d50, lsl #16`) y hace
`out[i] = in[i] XOR key[i % 12]`; `pEncrypt` @0x14a928 = xor → hex,
`pDecrypt` @0x14aed0 = hex → xor (nibble final suelto permitido). La
clave es idéntica a la de HX/TRM/Handsome/RJC, pero verificada aquí
byte a byte en la librería propia de Fx.

Prueba con datos reales de la app: el asset `server.psi` (103.301
caracteres hex, SHA-256 `8d087d9c…`, byte-idéntico en las 5 apps de la
familia) descifra con esta clave a través del doble hex del vendor
(quitar 1 char hex inicial, fase XOR 7, descifrar el texto hex
recuperado por líneas) a **22 entradas JSON válidas de servidor
Psiphon** (17 campos cada una; la 1ª de 23 segmentos queda truncada en
su apertura `{"`). Regiones: BR, DE, FR, GB, IN, JP, NL, PL, SG, US.

**`.sks`: no hay nada.** Ninguna referencia a `.sks` en el manifiesto,
en las 961 cadenas descifradas ni en el bytecode. No se construyó
ningún decodificador `.sks`.

## Psiphon (motor, no catálogo SP-DECODE)

`assets/server.psi`: lista de servidores Psiphon (22 entradas).
`res/raw/psiphon_config`: `ClientVersion 166`,
`PropagationChannelId EE0B7486ACAE75AA`,
`SponsorId 67DDC3614847FCEA`, puertos proxy local 8080 (HTTP) y 10801
(SOCKS). `assets/prince.ovpn`: plantilla OpenVPN de ejemplo (CA
"KobZ").

## Esquemas de texto/enlaces — ninguno propio

El manifiesto no declara ningún intent-filter con esquema propio (solo
`genericidp`/`recaptcha` de Firebase Auth y el VIEW de `.fxt`). No se
construyó `Fx_Tunnel_textos.py`. **`fxt://`:** no aparece en el
manifiesto ni en las 961 cadenas. `vmess://` solo aparece como
plantilla de configuración XRay (el motor construye el JSON de V2Ray
cuando el perfil usa vmess); no es un importador de enlaces de usuario.

## Auditoría HMAC

- Integridad de archivos: NOT_OBSERVED — los `.fxt` no tienen MAC ni
  firma; la integridad es solo estructural (JSON válido tras XOR).
- Integridad de catálogos: NOT_OBSERVED — el formato gremlin no tiene
  MAC; la validación estructural no equivale a autenticación
  criptográfica.
- Derivación criptográfica: NOT_OBSERVED — XXTEA con clave fija de
  formato y XOR repetido con clave fija; sin HMAC en la derivación.
- Transporte VPN: NOT_OBSERVED — Psiphon es el motor de transporte;
  no se revisó su autenticación de conexión en este expediente.
- Autenticación de conexión: NOT_OBSERVED — la actualización es GET
  sin autenticación (cuando se conozca la URL). La mera presencia de
  XXTEA/XOR no demuestra HMAC.

## Herramientas, por orden

1. Extracción del .apks (base + splits de ABI/idioma/dpi).
2. `strings` + androguard (DEX) y jadx 1.5.3 para localizar las clases
   de red, actualización y archivos.
3. Recuperación de las 961 cadenas LSParanoid del bytecode DEX.
4. Desensamblado de `libputils.so` con Capstone para verificar la
   clave XOR byte a byte.
5. Construcción de los scripts operativos (solo stdlib) y prueba
   contra el asset incluido y contra el asset `server.psi`.
6. Verificación de la regla SP-DECODE 2026-11-15: el JSON de resultado
   lleva solo los datos del catálogo, todo descifrado; las APIs de
   descarga NO van en el resultado.
