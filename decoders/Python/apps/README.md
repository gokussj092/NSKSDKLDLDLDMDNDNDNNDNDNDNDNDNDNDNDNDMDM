# Decodificadores organizados por aplicación

Cada aplicación de este lote tiene su propia carpeta, con nombres
reconocibles y espacios representados mediante guiones bajos:

- `Nombre_de_la_App.py`: lector exclusivo del catálogo, cuando exista.
- `Nombre_de_la_App_archivos.py`: lector exclusivo de archivos o textos,
  cuando se haya identificado ese formato.
- `Nombre_de_la_App.png`: icono original extraído de la aplicación.
- `README.md`: uso, formatos, evidencia y límites de validación.

Las incorporaciones Cloud guiadas por `SERVER_VPN_NEXT_CHAT_GUIDE.md` usan
`server_catalog_decoder.py`, `file_decoder.py`, `TESTING.md` y `manifest.json`.
Pueden reutilizar primitivas comunes; no requieren el APK para ejecutarse.

Los lectores son ejecutables independientes. Las muestras sintéticas y sus
productores se mantienen en `tests/golden`, y las pruebas en `tests`.

## Aplicaciones

| Aplicación | Catálogo | Archivos/textos | Icono y documentación |
| --- | --- | --- | --- |
| 24clan VPN Green 3.3 | [Script](24clan_VPN_Green/24clan_VPN_Green.py) | [.green](24clan_VPN_Green/24clan_VPN_Green_archivos.py) | [Carpeta](24clan_VPN_Green/README.md) |
| HX Tunnel VPN Hx-Build14 | [Script](HX_Tunnel_VPN/HX_Tunnel_VPN.py) | [.hxt](HX_Tunnel_VPN/HX_Tunnel_VPN_archivos.py) | [Carpeta](HX_Tunnel_VPN/README.md) |
| MKK Hyper VPN 2.9.2 | [Script](MKK_Hyper_VPN/MKK_Hyper_VPN.py) | [Texto mkk://](MKK_Hyper_VPN/MKK_Hyper_VPN_textos.py) | [Carpeta](MKK_Hyper_VPN/README.md) |
| My Tunnel Proxy 2.3 | [Script](My_Tunnel_Proxy/server_catalog_decoder.py) | [.mtp y mytunnelproxy://](My_Tunnel_Proxy/file_decoder.py) | [Carpeta](My_Tunnel_Proxy/README.md) |
