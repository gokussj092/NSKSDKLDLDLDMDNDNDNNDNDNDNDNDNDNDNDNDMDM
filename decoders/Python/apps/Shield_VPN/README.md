# Shield VPN (Litron Shield) — litron.shield.vpn 18.0 / build 18

Catálogo de Shield VPN para SP-DECODE. Python 3.10+, solo stdlib.

## Método (verificado en este APK)

La app es un fork de NekoBox (SagerNet) con frontal SocksHTTP/UltraSSH
(`com.slipkprojects.sockshttp`, `com.slipkprojects.ultrasshservice`) y
descarga su catálogo como suscripción NekoBox desde GitHub Pages:

```
GET https://godtechprime.github.io/shieldneko.txt
```

GET plano, sin headers propios ni autenticación. La URL aparece tres
veces en `classes.dex`. GitHub Pages la sirve con cualquier User-Agent;
verificado byte a byte con UA Dalvik y con urllib plano.

El cuerpo es una sola línea de Unicode invisible (U+2000..U+200F, cada
carácter es un nibble; dos caracteres son un byte) → Base64 → AES-256-CBC
PKCS#7, clave = SHA-256 del HEX EN MAYÚSCULAS de `godtech25` (o sea, del
ASCII `"474F44544543483235"`), IV = 16 bytes cero. Es el mismo formato de
la familia Litron del repo de SP-DECODE (`Litron_VPN` / com.fleet.vpn,
`Litron_Pro_VPN` / com.litron.udp); la salida de este script es idéntica
a la del codec del repo (verificado con PyCryptodome en asset y en vivo).

El JSON trae `Version`, `ReleaseNotes`, `Servers[]` y `Networks[]`. Cada
valor de texto formado solo por caracteres del portador se abre con el
mismo procedimiento (en el catálogo en vivo son `ServerUser`,
`ServerPass`, `cfrUser` y `cfrPass` de cada servidor).

## Resultado en vivo (2026-11-13, `--url`)

- HTTP 200, 360,456 bytes,
  SHA-256 `69eb22c155b86d39ff89067d504e82fcd1139f89b567a6adab5fa120abe338c7`
- **Versión 31.73, 8 servidores, 65 redes (payloads)**
- Servidores (todos `litrons.tech:80`, SSL 443, pass `0000`):
  GERMANY (premium), FRANCE (premium hq), CANADA (gaming),
  UNITED KINGDOM (gaming), Spectranet only 1 y 2, Ghana Server only 1 y 2
- De las 65 redes: 44 con Payload, 12 con SNI, 13 con V2RAY, 5 con Slowdns
- El catálogo no marca free/premium con un campo propio; solo `sInfo`
  dice "premium server" en 2 de los 8.

El asset incluido en el APK (`assets/config/config.json`) abre con el
mismo método: **Version 1, 5 servidores, 15 redes** (host `litrong.tech`).

## Uso

```
python3 Shield_VPN.py --url                  # descarga y muestra el JSON
python3 Shield_VPN.py --url -o catalogo.json # lo guarda
python3 Shield_VPN.py config.json            # decodifica un archivo local
python3 Shield_VPN.py --self-test            # asset incluido (v1, 5/15)
```

La descarga puede tardar ~30-40 s a través de proxy; el descifrado en
Python puro tarda ~6-10 s. CBC no autentica los datos: una clave o un
cuerpo incorrectos fallan en el padding y el script no entrega nada
parcial.

## Archivos de configuración

La app **no tiene formato propio de archivo importable**: el manifest no
declara ningún `ACTION_VIEW` de archivos ni extensión propia, y no hay
extensión en el DEX. Por eso no hay `Shield_VPN_archivos.py`. Su
configuración vive en la suscripción (este catálogo) y en el almacén
interno de la app.

## Enlaces de texto

El `MainActivity` de NekoBox declara los esquemas estándar
`sn://subscription`, `clash://install-config`, `sn://`, `ss://`,
`ssr://`, `socks://`, `socks4://`, `socksa://`, `sock5://`, `vmess://`,
`trojan://`, `trojan-go://`, `naive+https://`, `naive+quic://` e
`hysteria://`. No existe un esquema propio como `shield://`. Esos
protocolos estándar ya los cubre SP-DECODE.

## Archivos

- `Shield_VPN.py` — decodificador del catálogo (decode() + run() + CLI)
- `config.json` — asset incluido en el APK, para `--self-test`
- `Shield_VPN.png` — icono 512×512

## Pendiente

- Nada de muestras: el catálogo está verificado en vivo de extremo a
  extremo. Si el servidor rota la clave o cambia la URL, el script
  fallará en el padding (sin entregar datos parciales) y habrá que
  re-analizar el APK.
- No confundir con `com.litron.udp` (Litron Pro, ya cubierta en el repo)
  ni con `com.fleet.vpn` (Litron VPN base, ya cubierta en el repo):
  este proveedor es `litron.shield.vpn`, distinto, aunque comparte el
  formato de catálogo de la familia Litron.
