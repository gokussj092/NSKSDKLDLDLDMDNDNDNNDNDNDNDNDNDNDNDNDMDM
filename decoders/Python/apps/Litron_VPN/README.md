# Fleet VPN / LITRON VPN (com.fleet.vpn) 3.5.9, build 25

Catálogo de LITRON VPN, verificado en este APK y en vivo.

## Método (verificado en el APK, versionCode 25)

- Descarga: `GET https://godtechprime.github.io/latestv2ray.txt`
  (User-Agent `okhttp/5.0.0-alpha.3`, `Accept-Encoding: identity`,
  sin redirecciones ni autenticación; en el APK es `vagol.doInBackground`,
  un GET plano con OkHttp).
- El cuerpo es texto UTF-8 en un portador de nibbles Unicode: cada
  carácter es U+2000..U+200F y cada par codifica un byte (nibble alto
  primero). **Nunca hacer strip() del cuerpo**: parte del alfabeto es
  espacio Unicode.
- Desempaquetar pares -> bytes -> Base64 (canónico) -> AES-256-CBC,
  clave = SHA-256 del hex en mayúsculas de `godtech25`,
  IV = 16 bytes cero, PKCS#7 -> JSON `{Version, Servers, Networks, ...}`.
- Cada valor de texto formado solo por caracteres del portador es un
  campo oculto: desempaquetar -> probar Base64 -> AES-CBC; si no,
  bytes crudos -> AES-CBC; si no, UTF-8 empaquetado como nibbles.
- El mismo formato lo usa el asset incluido `assets/config/config.json`
  (v12) y el `Config.json` que la app guarda en `filesDir` tras descargar
  (`lh0.c()` lee `Config.json` si existe, si no el asset).
- CBC no autentica: descifrar prueba el formato, no el origen.

## Cobertura previa del repo (verificada, no asumida)

El repo ya cubría este app y este build en `analysis/com.fleet.vpn/25/`
y `decoders/Python/apps/Litron_VPN/` (método aportado por el propietario,
verificado con oráculo JCA independiente). Verificación hecha aquí en
este APK:

- APK base SHA-256 `8d3818e7...1f24a52` — **idéntico** al `sourceApkSha256`
  del repo; certificado firmante SHA-256 `ead8ad35...1a11f7` — idéntico.
- `lh0.b = "godtech25"`, `lh0.c()` lee `config/config.json` o
  `Config.json` y descifra con `q.f`; `q` = AES/CBC/PKCS7Padding,
  IV 16 ceros, `q.d` hex en mayúsculas, `q.l` SHA-256, `q.g` el
  alfabeto U+2000..U+200F (guardado como Base64 de sus bytes UTF-8),
  `q.k`/`q.n` desempaquetar/empaquetar nibbles.
- `vagol` hace GET plano a `https://godtechprime.github.io/latestv2ray.txt`.
- Asset incluido: 59,520 bytes, v12, 5 servidores / 5 redes,
  20 campos ocultos — igual que el repo.
- En vivo: 40 campos ocultos, igual que el repo (v289).

Diferencia con el repo: el script del repo (`Litron_VPN/codec.py`)
necesita PyCryptodome y el validador compartido de BD_NET_VPN.
`Fleet_VPN.py` es autocontenido con **solo la biblioteca estándar**
(AES puro en Python, mismo núcleo ya usado en AR PRO) y formato
SP-DECODE (`decode()` + `run()` + CLI `--url` / `--self-test`).

## Resultado en vivo (2026-11-13)

- HTTP 200, 446,856 bytes, SHA-256
  `209b15fd112fe99d44163410987edebfcda74b46c824ebbd27f70189e4bfb96a`.
- **Version 293, 8 servidores, 86 networks (72 con Payload no vacío)**.
  El repo registró v289 (444,168 bytes) el 2026-11-09: el catálogo
  cambió de versión pero el formato y los conteos son los mismos.
- El catálogo no marca free/premium/VIP en ningún campo: los 8
  servidores se sirven a todos los usuarios.
- Servidores: GERMANY, FRANCE, CANADA, UNITED KINGDOM,
  Spectranet Server only 1/2, Ghana Server 1/2 Only.

## Uso

```sh
python3 Fleet_VPN.py --url                  # descarga y muestra el catálogo
python3 Fleet_VPN.py config.json            # descifra el asset incluido
python3 Fleet_VPN.py --url -o catalogo.json # descarga y guarda el JSON
python3 Fleet_VPN.py --self-test            # 6/6 contra el asset incluido
```

`decode(bytes)` -> dict, `run(bytes)` -> texto JSON.

## Archivos

- `Fleet_VPN.py` — decodificador autocontenido (stdlib).
- `Fleet_VPN.png` — icono 512x512 (del `icon.png` 500x500 del XAPK).
- `config.json` — asset incluido del APK, para `--self-test`
  (v12, 5 servidores / 5 redes).
- Sin `Fleet_VPN_archivos.py`: la app no tiene formato propio de
  archivo importable (sin intent VIEW de archivos ni GET_CONTENT en
  el manifiesto); el archivo de catálogo en sí (`config.json` o el
  cuerpo descargado) se descifra pasando la ruta a `Fleet_VPN.py`.
- Sin esquema de texto propio: el manifiesto solo declara los
  esquemas estándar de SagerNet (`vmess://`, `ss://`, `trojan://`,
  `ssr://`, `socks://`, `hysteria://`, `sn://`, `clash://`, ...);
  no hay `litron://` ni `fleet://`.

## Pendiente

- Nada para cerrar el método: catálogo verificado en vivo de extremo
  a extremo. Si el servidor cambia la URL o la semilla, el script
  dejará de abrir y habrá que re-analizar el APK nuevo.
- No confundir con Litron Pro VPN (`com.litron.udp`, app distinta):
  su método e icono son independientes y no se reutilizan aquí.
