# HTTP WinzapVPN — 1.1.61 (76)

Paquete `com.winzap.winzap_vpn`, Flutter + motor nativo Kotlin
(`WinzapVpnService`, `VpnBridge`) + V2Ray/Hysteria/ZIVPN/SSH; proveedor
fijo `winzap-vpn`, integrado en la nube siguiendo el patrón GCP/NetFlux/
Maya (broker HTTPS fijo, worker aislado, contrato de documento completo,
control administrativo individual). Python >=3.10,
`pycryptodome>=3.18.0` y `requests>=2.31.0`. No necesita APK, SO,
Android ni cuenta en runtime.

## Métodos confirmados

| Entrada | Descifrado | Salida |
| --- | --- | --- |
| Catálogo bootstrap (`GET /api/v1/bootstrap?device_id=…`) | JSON en claro, sin firma ni sobre cifrado; validación + redacción a solo datos de catálogo | JSON con `app`, `package`, `version`, `version_code`, `config_version`, `countries` (con `servers`) |
| Blob `Winzap01` (`encrypted_mobile_config` del perfil) | Base64 → `Winzap01` + salt(8) + AES-256-CBC, clave/IV EVP_BytesToKey-MD5 sobre la clave maestra de la app; campos de capa 3 AES-256-CBC + ROT13, claves cortas → largas | Perfil con `Name`, `ServerIP`, `Payload`, `SNI`, etc. |
| Archivos | — | La app no registra sufijo de archivo ni importa configuraciones por archivo |
| Texto / esquemas | — | Sin esquema propio (`winzap://` no existe) |

Este módulo **no trae `file_decoder.py` a propósito**: la app no tiene
formato de archivo, así que un wrapper sería código muerto; el
precedente `RMP_TUNNEL_PRO`/`Maya_Tun_Pro` envía módulos solo-catálogo
igual. Tampoco trae ruta de texto: no hay esquema que despachar en
`text_bridge.py`.

**El bootstrap no autentica criptográficamente nada.** Es JSON en claro
por HTTPS; la validación es de estructura (países/servidores presentes,
`id`/`name` por servidor), no de autenticidad. Si falta
`config_version`, `countries` o algún servidor, el lector rechaza el
catálogo completo. HMAC de autenticación de conexión: `NOT_OBSERVED`
(ver dossier).

## Fuentes comprobadas

Única URL del bootstrap de este build (cadena en `libapp.so`):

`https://vpnapi.winzapg.online:2083/api/v1/bootstrap?device_id=WINZAP-TEST0001`

Lectura pública autorizada del 2026-11-23: **HTTP 200, 249,350 bytes,
`config_version` 1, 19 países, 177 servidores, 0 VIP**; dos descargas
seguidas byte-idénticas (solo los contadores volátiles `online_users`
cambian entre ventanas). El catálogo creció desde la ventana del
2026-11-22 (174 servidores): 3 altas, 0 bajas. El servidor anuncia
`latest_version` **1.1.62** — un build más nuevo que el 1.1.61
analizado; no se afirma compatibilidad con él. El bootstrap sin
`device_id` responde 422 (`Field required`); el perfil por servidor
exige la firma HMAC de la app (no reproducida) y responde 401 sin
ella. El CLI HTTPS real, CLI stdin y worker aislado entregan el mismo
documento completo con fixtures sintéticos; el catálogo en vivo se
valida en ~2 s por el mismo codec (límite del worker de catálogos:
120 s). No se guardan en Git catálogos reales, valores descifrados,
sesiones ni credenciales.

Se preservan orden, metadatos, listas, valores vacíos, nulos y tipos.
Los campos volátiles `online_users` se sirven tal cual (son datos del
catálogo, como en la redacción de referencia). No se eligen hosts,
sustituyen marcadores ni inician conexiones VPN. Sin créditos dentro
del script ni del resultado.

## Uso

```bash
python server_catalog_decoder.py --download
python server_catalog_decoder.py copia-catalogo.json
python server_catalog_decoder.py --stdin < copia-catalogo.json
```

Los lectores de catálogo exponen `run(data: bytes) -> str`; el blob
expone `codec.decode_winzap01_blob("<base64>") -> dict`. No se aportó
un blob `Winzap01` real ni un perfil firmado; el blob queda en
`VERIFIED_SYNTHETIC` (round-trip con el método del DEX). No se
certifica un roundtrip de exportador Android (la app no exporta).

## Cloud

- Bridge privado, worker aislado, contrato de documento completo y
  control administrativo individual. Una URL HTTPS fija con puerto
  2083 y `device_id` fijo, DNS IPv4 público validado, TLS y ninguna
  redirección; el cliente no puede elegir destinos. El puerto no
  estándar obliga a un descargador dedicado en el broker (la ruta
  genérica rechaza cualquier puerto distinto de 443; mismo patrón que
  AM Tunnel Lite / OpenTunnel / Tunneltweak).
- PNG del icono launcher del .apks 1.1.61, **bytes exactos del APK**
  (`res/mipmap-xxxhdpi-v4/ic_launcher.png`, 192×192, **21,447 bytes**;
  no remuestreado a 512×512).
- Catálogo mínimo **98**; conserva switches y versión persistente.
  La entrega deja código en el árbol, sin push ni despliegue.
- Dossier y pruebas: `analysis/com.winzap.winzap_vpn/76/` y
  [pruebas](TESTING.md).
