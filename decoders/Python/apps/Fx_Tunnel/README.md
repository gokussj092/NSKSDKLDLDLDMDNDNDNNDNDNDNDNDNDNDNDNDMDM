# Fx Tunnel — catálogo empaquetado, archivos .fxt y Psiphon

App: Fx Tunnel, paquete `com.fx.tunnel`, versionCode 39, versionName
4.8, minSdk 24, targetSdk 36. APK analizado:
`apks/Fx_Tunnel_4.8_3_5n8f.apks` (39.701.734 B), SHA-256
`c6c5ef8c2f759499435182a9eb762ba1cec67a55182f50f5b2e08e9561b2c291`
(base.apk + splits `split_config.arm64_v8a` / `.es` / `.xhdpi`).

## Catálogo

- **Formato:** `assets/gremlin.json` (665.036 B) es Base64 → XXTEA
  (delta `0x9E5729B1`, palabras little-endian, longitud original en la
  última palabra) → JSON UTF-8. La clase XXTEA es `AbstractC1765nm`
  (`nm`) en `classes2.dex`; su clave `a` es la cadena LSParanoid
  `-4663933677235715084`. La clave es propia de Fx: con la clave de
  las apps hermanas (`Princie!`) el asset falla con longitud interna
  XXTEA inválida; con la clave de Fx abre.
- **Empaquetado (descifrado y verificado):** Version **10288**,
  29 servidores libres, 0 premium / VIP / privados, **1353 payloads**.
  Secciones: `Premium_servers`, `Vip_servers`, `Private_servers`,
  `Username`, `Password`, `Free_servers`, `Payloads`, `Version`,
  `Changelogs`.
- **En vivo: URL NO RECUPERADA (fallo honesto).** La clase
  `rased.vpn.app.activities.OpenVPNClient` (donde vive el updater en
  las apps hermanas) no está definida en ninguno de los tres DEX; la
  capa UI está protegida por LIAPP v5.1.1.190 y se carga en tiempo de
  ejecución. Las 961 cadenas LSParanoid recuperadas no contienen
  ninguna URL de updater. **No se inventó ninguna URL ni se probó
  ninguna sustituta.** En cuanto se conozca la URL (p. ej. capturada
  en un teléfono con la app instalada), `Fx_Tunnel.py --url <URL>`
  descarga y descifra con la clave ya verificada.
- **Cómo sirve el servidor este catálogo (decisión de Pedro
  2026-11-17):** el servidor sirve el `bundled.json` ya descifrado
  (v10288) DIRECTAMENTE, sin ejecutar el script de descifrado por
  pedido y sin descarga. Ver el expediente
  `analysis/com.fx.tunnel/39/` y `REPORT.md` en el staging: el
  mecanismo es un marcador `spdecode-supplied-bundled-v1` que el
  worker resuelve leyendo el `bundled.json` almacenado junto al
  módulo (sin red, sin XXTEA); la variante literal sin Python
  requeriría una rama nueva en el gateway y queda como pregunta
  abierta para Pedro/Codex.

## Uso

```sh
python3 Fx_Tunnel.py --apks apks/base.apk -o catalogo.json   # empaquetado
python3 Fx_Tunnel.py --apks apks/base.apk --summary           # solo recuentos
python3 Fx_Tunnel.py --url <URL> --summary                   # remoto, cuando se conozca la URL
python3 Fx_Tunnel_archivos.py archivo.fxt -o perfil.json     # archivo .fxt
python3 Fx_Tunnel_archivos.py --self-test                    # round-trip 5/5 + server.psi
python3 Fx_Tunnel_archivos.py --psi server.psi -o psi.json   # asset Psiphon
```

Solo biblioteca estándar (Python 3.10+). Sin URL por defecto en
`Fx_Tunnel.py` (`CATALOG_URL = None`).

## Archivos `.fxt`

- **Formato:** texto hexadecimal (una línea) → XOR repetido (clave de
  12 bytes) → UTF-8 modificado JNI (CESU-8) → JSON. Sin salt, IV, MAC
  ni firma.
- **Clave verificada contra la `libputils.so` propia de Fx**
  (split arm64, SHA-256
  `e3e8d9e06dee7e98775ffd76c0bac438e2e6d5e1bb6be2e78f1157ebd501c758`):
  `xorWithKey` @0x1496d4, `pEncrypt` @0x14a928, `pDecrypt` @0x14aed0.
  La clave es idéntica a la de HX/TRM/Handsome/RJC, pero verificada
  aquí byte a byte en la librería propia de Fx.
- **Prueba con datos reales de la app:** el asset `server.psi`
  descifra a **22 entradas JSON válidas de servidor Psiphon**.
- **Self-test:** round-trip 5/5 (15, 4, 3, 1 y 2 campos; incluye
  unicode/CESU-8, carácter fuera del BMP, NUL embebido y valor de
  5.000 caracteres; también con el hex en mayúsculas).
- **Políticas** (`tweak_password`, `tweak_expiry`, `hwid_lock`,
  `block_rooted`): se verifican DESPUÉS de descifrar; no derivan la
  clave. El lector recupera todos los campos sin ejecutarlas, así que
  el formato no declara campos de credenciales (`credentialFields:
  []`).
- **Pendiente:** un `.fxt` real exportado por Fx Tunnel 4.8, solo para
  confirmar el extremo a extremo.
- **`.sks`: no hay nada.** Ninguna referencia en el manifiesto, en las
  961 cadenas ni en el bytecode.

## Psiphon (motor, no catálogo SP-DECODE)

`assets/server.psi`: 22 entradas de servidor Psiphon (ver
`server_psi.json` en el material de trabajo). `res/raw/psiphon_config`:
`ClientVersion 166`, `PropagationChannelId EE0B7486ACAE75AA`,
`SponsorId 67DDC3614847FCEA`, puertos proxy local 8080 (HTTP) y 10801
(SOCKS).

## Esquemas de texto/enlaces — ninguno propio

El manifiesto no declara ningún intent-filter con esquema propio (solo
`genericidp`/`recaptcha` de Firebase Auth y el VIEW de `.fxt`). No hay
`fxt://`. `vmess://` solo aparece como plantilla de configuración
XRay; no es un importador de enlaces de usuario.

## Probado (2026-11-17)

- `Fx_Tunnel.py --apks apks/base.apk` reproduce `bundled.json` byte
  por byte (Version 10288, 29 libres, 1353 payloads).
- `Fx_Tunnel_archivos.py --self-test`: 5/5.
- `Fx_Tunnel_archivos.py --psi` sobre el asset reproduce
  `server_psi.json` (22 entradas, idéntico).
- El JSON de resultado (`bundled.json`) contiene solo los datos del
  catálogo, todo descifrado; no incluye ninguna API de descarga.
