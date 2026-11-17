# GOOD VPN — catálogo y archivo profile.json

App: GOOD VPN, paquete `com.ovpnsevice.goodvpn`, versionCode 30,
versionName 3.0, desarrollador NAMO DATA NETWORK. APK verificado: XAPK
de APKPure 34.805.320 B, SHA-256
`792e46ae687fb38dc215431295019420ddb78c4ea3b0f3be7780e36d5f70ab0c`
(base 10.263.875 B, SHA-256
`e99f78b0df30e7318ae63548bfa2cb1beb22ac3139005624077931c980039946`).
No confundir con PPH GOOD VPN (`com.skphvpn.mm`, `pph-good-vpn` del
repo): otra app, otro paquete, otro catálogo.

## Catálogo (GET plano, URL fija, sin auth)

- Endpoint (URL fija devuelta por el nativo `MainDetail.a()` en
  `libapi-good.so`):
  `GET https://raw.githubusercontent.com/Anurak2534/ohmvpn/refs/heads/main/newgood.json`
- Petición replicada: GET plano, `User-Agent: okhttp/5.2.1` (el UA por
  defecto de la pila OkHttp 5.2.1 de la app), sin cabeceras propias ni
  cuerpo. El servidor responde 200 a cualquier User-Agent.
- Descifrado (`nc0`): Base64 estándar artesanal → XXTEA (variante con
  delta `0x2E0BA747`, clave `goodvpn090529` de `MainDetail.b()`,
  rellenada con ceros hasta 16 bytes, tamaño original en la última
  palabra) → JSON UTF-8 completo. Sin MAC.
- Valores internos en Base64: varios campos del catálogo vienen a su vez
  en Base64 y la app los descifra al usarlos con `od.h`. El script
  descifra exactamente esos campos: en Servers `ServerIP`, `Username`,
  `Password`, `setOpenVPN`, `V2Ray`, `ServerDNS`, `Cloudfront`,
  `NameServer`, `PublicKey`, `UDPConfig`; en Networks `Payload`,
  `SquidProxy`, `Sni`; y `setOpenVPN` a nivel superior. Un campo que no
  descifre se deja como está y se reporta en `undecoded_fields` (en vivo:
  ninguno).

## Uso

```sh
python3 Good_VPN.py --url --summary     # descarga en vivo, solo recuentos
python3 Good_VPN.py --url -o live.json  # guarda el catálogo descifrado (no sobrescribe)
python3 Good_VPN.py respuesta.txt --summary  # cuerpo guardado
python3 Good_VPN_archivos.py --self-test     # 3/3 ok (round-trip sintético)
```

Solo biblioteca estándar (Python 3.10+). `--summary` solo emite versión
y recuentos, nunca valores descifrados. `Good_VPN.py` expone
`decode()` + `run(bytes) -> str`; `Good_VPN_archivos.py` expone
`decode()` + `run(bytes) -> str`.

## Probado (2026-11-17, re-corrido en vivo el mismo día)

- En vivo: versión 21.8, 13 servidores, 14 payloads (Networks),
  `undecoded_fields: []`.
- Re-corrida en vivo byte por byte idéntica al `live.json` entregado.
- El cuerpo vivo guardado `newgood.json` (69.065 B) abre con
  `Good_VPN.py` y con `Good_VPN_archivos.py` con los mismos recuentos.

## Archivos y texto

- **La app NO importa archivos de configuración del usuario.** El
  manifiesto no tiene ningún intent-filter VIEW para archivos, no hay
  ninguna actividad que maneje `ACTION_GET_CONTENT` /
  `ACTION_OPEN_DOCUMENT`, y no hay selector de archivos. El único
  archivo que la app lee es su propio catálogo en caché,
  `filesDir/profile.json`, escrito con `od.g` (XXTEA cifrar + Base64) y
  leído con `an2.c` — exactamente el mismo formato cifrado que la
  respuesta remota. `Good_VPN_archivos.py` lo descifra.
- **Sin esquema propio de texto.** No hay intent-filter con esquema
  propio; no hay `goodvpn://`. `vmess://` / `vless://` / `trojan://` /
  `ss://` aparecen solo dentro de la librería v2rayNG empaquetada, que
  parsea el campo `V2Ray` del propio servidor del catálogo. No hay UI
  para pegar/importar enlaces del usuario.

## Pendiente

1. Confirmación de punta a punta: instalar GOOD VPN 3.0 en un teléfono
   y comparar su lista de servidores (13 servidores, versión 21.8) con
   `live.json`.
2. No existe ningún `profile.json` real extraído de un teléfono; el
   formato ya está verificado contra la respuesta remota en vivo, que es
   idéntica.
3. El catálogo vive en un repositorio público de GitHub
   (`Anurak2534/ohmvpn`, rama main, `newgood.json`); si el operador
   cambia la URL, la clave o el formato, el script dejará de descifrar y
   deberá re-analizarse el APK nuevo (la clave vive en
   `libapi-good.so`, no en el DEX).

Expediente: `analysis/com.ovpnsevice.goodvpn/30/`.
