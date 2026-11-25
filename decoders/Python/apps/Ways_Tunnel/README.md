# Ways Tunnel — 18.1 (18)

Paquete `com.ways.tunnel`, Pausa Studio (misma familia que Pausa VPN /
M Light); proveedor fijo `ways-tunnel`, integrado en la nube siguiendo
el patrón WinzapVPN/GCP/NetFlux/Maya (broker HTTPS fijo, worker
aislado, contrato de documento completo, control administrativo
individual). Python >=3.10, `cryptography>=41.0` (sin ella,
`waystunnel.py` usa el CLI `openssl`). No necesita APK, SO, Android
ni cuenta en runtime.

## Métodos confirmados

| Entrada | Descifrado | Salida |
| --- | --- | --- |
| Catálogo vivo (`GET .../politicas/.../config.json?t=<millis>`) | Glifos → Base64 → AES-256-CBC, clave SHA-256 del hex en mayúsculas de `dam0n`, IV cero, PKCS7; validación + redacción a solo datos de catálogo | JSON con `Version`, `ReleaseNotes`, `Servers` (5) y `Networks` (78) |
| Tweak `wyst://` | Mismo AES/CBC con IV cero, clave de `tweakdam0n`; se parsea como JSONObject | Documento `{"application", "protocol", "config"}` |
| Archivos | — | La app no registra sufijo de archivo ni importa configuraciones por archivo |
| Premium | — | Sin catálogo premium separado verificable (v1.0.49 no tiene ningún campo VIP/premium; la app descarga este único `config.json`) |

Este módulo **no trae `file_decoder.py` a propósito**: la app no tiene
formato de archivo, así que un wrapper sería código muerto; el
precedente `WinzapVPN`/`RMP_TUNNEL_PRO`/`Maya_Tun_Pro` envía módulos
solo-catálogo igual. La ruta de texto vive en `text_decoder.py`
(`wyst://`, VERIFIED_SYNTHETIC — falta una muestra real).

**El catálogo no autentica criptográficamente nada.** Es texto de
glifos por HTTPS público; la validación es de estructura (versión,
servidores y networks presentes, `Name` por fila), no de
autenticidad. Si falta `Version`, `Servers` o `Networks`, o alguna
fila no tiene `Name`, el lector rechaza el catálogo completo. HMAC
de autenticación de conexión: `NOT_OBSERVED` (ver dossier).

## Fuentes comprobadas

Única URL del catálogo de este build (cadena LSParanoid, usada solo
en `MainActivity`):

`https://raw.githubusercontent.com/waystunnel/politicas/refs/heads/main/config.json`

Lectura pública autorizada del 2026-11-24: **HTTP 200, 276,225 bytes
UTF-8 (92,800 glifos) → 36,007 B JSON, SHA-256
`468725bbef20019fbd48d84b0029e5912ee30df8518b428413b5202305aa7b10`,
versión 1.0.49, 5 servidores, 78 networks**; dos descargas
reproducidas con bytes descifrados byte-idénticos. El CLI HTTPS real,
CLI stdin y worker aislado entregan el mismo documento redactado con
fixtures sintéticos; el catálogo en vivo se valida por el mismo codec
(límite del worker de catálogos: 120 s). No se guardan en Git
catálogos reales, valores descifrados, sesiones ni credenciales.

Se preservan orden, metadatos, listas, valores vacíos y tipos. Los
campos de redacción eliminan las credenciales de servidor
(`ServerIP`, `ServerUser`, `ServerPass`, `ProxyIP`, `SlowChave`,
`TokenAuth`, `NameServer`, `udpserver`, `udpobfs`, `udpauth`,
`OpenVPNConfig`, `v2rayJson`), `SlowDns`/`OpenVPNConfig`/`v2rayJson`
de networks y el enlace de invitación `WhatsApp`. No se eligen hosts,
sustituyen marcadores ni inician conexiones VPN. Sin créditos dentro
del script ni del resultado.

## Uso

```bash
python server_catalog_decoder.py --download
python server_catalog_decoder.py copia-catalogo-cifrado.txt
python server_catalog_decoder.py --stdin < copia-catalogo-cifrado.txt
python text_decoder.py 'wyst://...'
python waystunnel.py --self-test
```

Los lectores de catálogo exponen `run(data: bytes) -> str`; el tweak
expone `text_decoder.decode_text("wyst://...") -> str | None`. No se
aportó un tweak `wyst://` real; el tweak queda en
`VERIFIED_SYNTHETIC` (round-trip con el método del DEX). No se
certifica un roundtrip de exportador Android (la app no exporta).

## Cloud

- Bridge privado, worker aislado, contrato de documento completo y
  control administrativo individual. Una URL HTTPS fija en el host
  `raw.githubusercontent.com` (443, sin puerto no estándar), GET
  plano sin cabeceras ni auth — exactamente como la app — por la ruta
  genérica del broker; el `?t=<millis>` es solo anti-caché de la app
  y el broker no lo necesita (GitHub sirve el contenido vigente).
  El cliente no puede elegir destinos.
- PNG del icono launcher del .apks 18.1, **bytes exactos del APK**
  (`res/drawable/icon.webp`, que son bytes PNG, 1280×1279,
  **718,879 bytes**; no remuestreado).
- Catálogo mínimo **99** (lo sube el coordinador, una sola vez
  98 → 99 para toda la entrega); conserva switches y versión
  persistente. La entrega deja código en el árbol, sin push ni
  despliegue.
- Dossier y pruebas: `analysis/com.ways.tunnel/18/` y
  [pruebas](TESTING.md).
