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
| Robust Tunnel VPN isvsoft 16.4.7 | [Script](Robust_Tunnel_VPN/server_catalog_decoder.py) | Copias del mismo catálogo, sin extensión obligatoria | [Carpeta](Robust_Tunnel_VPN/README.md) |
| Royal Tunnel VPN 7.0 | [Script](Royal_Tunnel_VPN/server_catalog_decoder.py), remoto actualmente devuelve HTML | [.roy actualizado](Royal_Tunnel_VPN/file_decoder.py) | [Carpeta](Royal_Tunnel_VPN/README.md) |
| TRV TUNNEL 2.4 | [Script](TRV_TUNNEL/server_catalog_decoder.py) | [.hxt, formato compartido verificado](TRV_TUNNEL/file_decoder.py) | [Carpeta](TRV_TUNNEL/README.md) |
| AustroPlus VPN 13.0.1 | [Script](AustroPlus_VPN/server_catalog_decoder.py) | [.aro actual AES-GCM](AustroPlus_VPN/file_decoder.py) | [Carpeta](AustroPlus_VPN/README.md) |
| AC TUNNEL VPN 1.4 | [Script](AC_TUNNEL_VPN/server_catalog_decoder.py) | [.actun, actunnelvpn:// y referencia acvpn://](AC_TUNNEL_VPN/file_decoder.py) | [Carpeta](AC_TUNNEL_VPN/README.md) |
| 4U TUNNEL LITE 2.2 | [Script](4U_TUNNEL_LITE/server_catalog_decoder.py) | [.4ulite y texto compatible](4U_TUNNEL_LITE/file_decoder.py) | [Carpeta](4U_TUNNEL_LITE/README.md) |
| HTTP FenixVPN 19.4 | [Servidores y usuarios](HTTP_FenixVPN/server_catalog_decoder.py) | [.sks GCM y DES](HTTP_FenixVPN/file_decoder.py) | [Carpeta](HTTP_FenixVPN/README.md) |

- [HTTP Jireh 2.0](HTTP_Jireh/README.md): archivos `.sks` GCM/DES con motor compartido, catálogo nibble/AES-CBC/ROT22 y usuarios separados; icono original.

- [Tunneltweak 6.2.1](Tunneltweak/README.md): `.tut` CBC/TTPBE1 con contraseña/XOR, catálogo público GCM y transporte Cloud UUID; icono original.

- [HTTP SocketClay 3.4.0](HTTP_SocketClay/README.md): catálogo WakkoDev/ChaCha20/AES con clave por versión y `.sks` GCM/DES compartido. Descarga dual de servidores/usuarios verificada y habilitada en el catálogo Cloud.

- [HTTP Wakko 4.9](HTTP_Wakko/README.md): catálogo completo de servidores/usuarios, clave nativa por versión y 29 campos de servidor incluidos slots BHTTP. Descarga dual real verificada; sin formato de perfil exportado identificado.

- [TunelGuard VPN 12.8](TunelGuard_VPN/README.md): `.tgv` AES-CBC y catálogo STGCM2.TG autenticado, con paridad Java/ARM64. Catálogo inicial validado; fuente remota responde 404 y su ficha permanece desactivada.

- [V2ray Tunnel Plus 10.0.0](V2ray_Tunnel_Plus/README.md): suscripciones públicas Base64 y URI en texto, con descarga dual completa y paridad Java. 150 perfiles por fuente observados, misma lista representada de dos formas; catálogo Cloud integrado con icono original.

- [EUT VPN 2.4.1](EUT_VPN/README.md): lector de recursos AES-CBC y worker aislado, validación breve con vectores JDK e icono original. Ficha remota desactivada: API exige sesión válida y el inicio de sesión rechaza el entorno.

- [Focus VPN Cloud 5.0](Focus_VPN_Cloud/README.md): catálogo de bloques Unicode/AES-CBC y 12 campos RC4, descarga real de 142 servidores verificada con JDK, CLI y worker aislado. Proveedor, control e icono original integrados.

- [FreedomVPN 1.0.29](FreedomVPN/README.md): catálogo XXTEA con delta propio y ocho campos XXTEA/AES-ECB/símbolos-AES-CBC. 147 servidores descargados y comparados íntegramente con JDK, CLI y worker; proveedor e icono original integrados.

- [HTTP Internet Infinito 1.3.9](HTTP_Internet_Infinito/README.md): catálogo WakkoDev/MD5/AES-CBC y 29 campos de servidor con ROT22; descarga real de 74 servidores comparada íntegramente con JDK, CLI y worker. Usuarios incluidos en el APK verificados offline; proveedor e icono PNG original integrados.

- [FlexNet V 2.4 / B46](FlexNet_B42/README.md): amplía el lector existente a v5 build 46, v6 con clave de setup autorizada y campos protegidos SNI/payload; conserva v1–v5 y B42. La muestra online aportada requiere su clave de contenido y no se presenta como descifrada.

- [MegaTunnel 1.17.1](MegaTunnel/README.md): catálogo AES-256-GCM y campos Base64/XOR, descarga real de 10 servidores y 124 ajustes íntegros comprobada con JDK, CLI y worker; proveedor e icono original integrados.
