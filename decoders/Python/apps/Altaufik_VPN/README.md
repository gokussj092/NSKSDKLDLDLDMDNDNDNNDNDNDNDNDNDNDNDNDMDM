# ALTAUFIK VPN — catálogo

App: ALTAUFIK VPN, paquete `net.tcodes.altaufikvpn`, versionCode 44,
versionName 5.01. APK verificado: `ALTAUFIK_VPN_5.01_0_m7hy.apks`
(34.116.543 B, SHA-256
`93c7ca977f38a7d5f8300a99dae4db04f2ad574e001601745d64f077ff6d33d3`;
base.apk + splits arm64/es/xhdpi).

Familia tcodes (misma que 24clan / EDOZ): mismo contenedor OpenSSL
Salted__, mismo SQLite `system.db` / `tcodes_table`, mismo cliente
Apache `DefaultHttpClient`. La constante de formato de esta app es
`mtscrypt` (la misma que 24clan; EDOZ usa `securedjson`). No es una
credencial de cuenta: es la contraseña del formato OpenSSL
(`M2/d.<clinit>`), necesaria para descifrar cualquier catálogo de la
familia.

## Catálogo

- **Descarga (app):** `MainActivity.L(Z Z)` → `F2/n` (AsyncTask) →
  Apache `DefaultHttpClient`, `HttpGet` sobre la URL tal cual, sin
  cabeceras propias, sin parámetros, sin token, sin sesión. El stack
  envía implícitamente `User-Agent: Apache-HttpClient/UNAVAILABLE
  (java 1.4)`; el script replica ese valor. El segundo booleano es la
  preferencia `use_vip`: `false` → URL gratis, `true` → URL VIP.
- **Endpoints:**
  - Gratis: `GET https://24clanvpn.com/updater/12e6a66d012aa0e8ae49de9dd9d1d4`
  - VIP: `GET https://24clanvpn.com/updater/6ccbf3270197580767739262e2bcef`
- **Descifrado (`M2/d.a`):** Base64 → contenedor OpenSSL `Salted__` →
  EVP_BytesToKey/MD5 (`mtscrypt`) → AES-256-CBC/PKCS#7 → JSON UTF-8.
  Si OpenSSL no puede descifrar, la app devuelve la entrada tal cual
  (el script admite JSON sin cifrar que empiece por `{`).

## Uso

```sh
python3 Altaufik_VPN.py --vip --url -o catalogo.json   # VIP en vivo
python3 Altaufik_VPN.py --url -o catalogo.json          # gratis en vivo
python3 Altaufik_VPN.py --vip --url --summary           # solo recuentos
python3 Altaufik_VPN.py --self-test                     # vector sintetico + rechazo del cuerpo muerto
```

Requiere PyCryptodome (`Crypto.Cipher.AES`); el resto es biblioteca
estándar (Python 3.10+).

## Probado (2026-11-17)

- VIP en vivo: v9.5, 7 servidores, 1458 tweaks (1343 con Payload).
  Re-corrido en vivo y comparado byte por byte con `live.json`:
  idéntico.
- Gratis en vivo: **MUERTO** — HTTP 200, cuerpo de 2 bytes (`ff`),
  `Last-Modified: Fri, 06 Oct 2023`. No descifra; el script devuelve
  `FORMAT_ERROR`. La app cae al catálogo integrado `assets/defconf`
  (v9.6, 4 servidores, 1486 tweaks). Ver `live_probe.json` en el
  material de trabajo y el expediente
  `analysis/net.tcodes.altaufikvpn/44/`.
- Integrado VIP `assets/vip_defconf`: v8.3, 7 servidores, 1568 tweaks.
- Nada sin descifrar: los dos catálogos integrados y el VIP en vivo
  descifran completos con `mtscrypt`. El JSON de resultado lleva solo
  los datos del catálogo, todo descifrado; no incluye APIs de descarga.

## Sin formato propio de archivo ni esquema de texto

La app **no tiene formato propio de archivo importable**: el manifest
no declara ningún intent-filter `ACTION_VIEW` para archivos ni esquema
URI propio (no hay `altaufik://` ni `tcode://`); tampoco hay código de
importación/exportación de perfiles (`.sks`, `.ehi`, `.hat`, etc.). La
única importación es la genérica de OpenVPN (`.ovpn`/`.conf`, de la
librería OpenVPN, no un formato propio). Los servidores/tweaks
personalizados se crean a mano en la UI y se guardan en `system.db`.
Tampoco hay esquema de texto propio: solo los enlaces estándar
`vmess://` dentro del JSON de servidores, que SP-DECODE ya cubre.

## Pendiente

- Confirmar en un teléfono que la app, con `use_vip=false`, muestra el
  catálogo integrado v9.6 y no se rompe con el endpoint gratis muerto
  (el código cae al integrado, pero no se probó en el dispositivo).
- Si el endpoint gratis vuelve a servir catálogo algún día, verificar
  que descifra con la misma contraseña (el script ya lo soporta con
  `--url`).
