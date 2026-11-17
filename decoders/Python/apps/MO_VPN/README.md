# MO VPN — catálogo y archivo guardado

App: MO VPN, paquete `com.movpn.vpnth`, versionCode 6, versionName 1.0.6.
APK verificado: XAPK de APKPure 37.551.062 B, SHA-256
`31397a90de90a32597e6e87dff9133c0cff913d0ae5a17a9c1d97f34ba90e92b`
(base 15.590.333 B, SHA-256
`bd27a1a998bb3ea0098ae6ee7d4778c301f085b20aa3ead42d9827fe7ee7fdc3`).
Misma plantilla que PNT VPN (mismo repo GitHub `sansoe2022/PNT_VPN`,
mismas librerías nativas, mismo asset `pntvpn.json`), con su propia clave
de catálogo y sus propios archivos `api.json` / `config.gen`. Es OTRA app
y OTRA ruta que el `pnt-vpn` del repo (`com.pntvpn.net`,
`sansoe2022/new_pntvpn`): no confundirlas.

## Catálogo (2 etapas, GET planos sin auth)

1. Índice (Volley `JsonObjectRequest` en la app):
   `GET https://raw.githubusercontent.com/sansoe2022/PNT_VPN/refs/heads/main/api.json`
   → JSON con `version` y `fileUrl`.
2. Catálogo (PRDownloader en la app):
   `GET https://raw.githubusercontent.com/sansoe2022/PNT_VPN/refs/heads/main/config.gen`
   → una línea Base64 → XXTEA (clase `SVPNDex`, DELTA `0xD1FBFA0B`,
   clave `com.movpn.paidapk`) → JSON con `FileName`, `Servers`,
   `HTTPNetworks`, `SSLNetworks`, `Ovpn_Cert`.
3. Campos cifrados de cada servidor/red (`FileUtils.showJson`): Base64 →
   XXTEA (clase `XxTea`, DELTA `0x3B2959AF`, clave `5741`) → texto UTF-8
   con caracteres portadores (U+2C00–U+2DFF) → cada carácter −5741 dos
   veces → texto plano. Campos: `ServerIP`, `ServerCloudFront`,
   `ServerHTTP`, `V2ray`, `SlowIP`, `PublicKey`, `Username`, `Password`,
   `NetworkPayload`, `SquidProxy`, `WSHost`, `Address`,
   `NetworkFrontQuery`, `NetworkBackQuery`.

Valores nativos recuperados emulando con Unicorn los JNI de
`libnative-sec.so` (`getApiUrl` @0x2ac4, `getAuthHash` @0x3c3c,
`getAesKey` @0x4d34, `getDelta` @0x5f30).

## SEGURIDAD — tokenKey excluido

El catálogo trae un campo `tokenKey` de 40 caracteres que es un token de
GitHub. NO se incluye en ninguna salida guardada (`-o`), NO lo imprime
ningún script y NO se reproduce en ningún documento: `MO_VPN.py` lo
elimina antes de escribir y `MO_VPN_archivos.py` lo elimina en
`decode()`. El valor nunca se escribió en ningún entregable.

## Uso

```sh
python3 MO_VPN.py --url              # descarga api.json + config.gen en vivo
python3 MO_VPN.py --url -o live.json # guarda el catálogo descifrado (sin tokenKey)
python3 MO_VPN.py --file pntvpn.json # descifra el asset del APK
python3 MO_VPN.py --self-test        # 8/8 ok (round-trip + asset)
python3 MO_VPN_archivos.py pntvpn.json --summary   # archivo guardado Config.json / pntvpn.json
python3 MO_VPN_archivos.py --self-test             # 9/9 ok
```

Solo biblioteca estándar (Python 3.10+). El resumen no imprime
credenciales de servidor.

## Probado (2026-11-17, re-corrido en vivo el mismo día)

- En vivo: API version 7, FileName `config.gen`, 13 servidores (10
  gratuitos Category 0 + 3 premium Category 2), 11 redes HTTP (9 con
  payload), 0 SSL. Cero errores de campo.
- Re-corrida en vivo byte por byte idéntica al `live.json` entregado.
- Asset `pntvpn.json` del APK abre con el mismo método: 13 servidores,
  11 redes, 0 errores de campo.
- `MO_VPN.py` expone `decode()` (catálogo crudo) + `decrypt_fields()`;
  su `run()` es la CLI (devuelve int), NO es un `run(bytes) -> str`.
  `MO_VPN_archivos.py` expone `decode()` + `run(bytes) -> str`.

## Archivos y texto

- **Sin formato propio de archivo de perfil.** El manifiesto declara 15
  actividades y NINGÚN intent-filter (sin `ACTION_VIEW`, sin esquemas,
  sin sufijos). No hay `.sks`, `.movpn` ni ningún otro sufijo. El único
  "archivo" es el catálogo guardado `<filesDir>/SVPN/Config.json` (cuerpo
  cifrado tal cual lo descarga la app) o el asset `pntvpn.json`, que abre
  `MO_VPN_archivos.py` con el mismo método.
- **Sin esquema propio de texto.** `vmess://` / `vless://` / `trojan://` /
  `ss://` solo aparecen como literales del fork de v2rayNG (importación
  estándar por portapapeles). No hay `MO_VPN_textos.py`.

## Pendiente

1. Un `Config.json` real guardado por MO VPN 1.0.6 en un teléfono (el
   método ya está verificado contra el cuerpo vivo y el asset).
2. Contador en línea (`http://<host>/server/online_app`): desde esta VM
   la conexión TCP falla; comprobar desde una red donde esos hosts
   respondan.
3. Si el servidor rota la clave, re-emular `libnative-sec.so` (ver
   `analysis/com.movpn.vpnth/6/REPRODUCE.md`).

Expediente: `analysis/com.movpn.vpnth/6/`.
