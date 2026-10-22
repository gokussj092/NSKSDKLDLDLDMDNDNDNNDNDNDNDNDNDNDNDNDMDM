# V2ray Tunnel Plus 10.0.0

Paquete `vpn.v2raytunnelplus.com.eg`, versionCode **4000010**. Lector Python
de suscripciones públicas para SP-DECODE Cloud, PR #96, rama
`feat/austroplus-vpn-13-0-1-decoders`.

## Catálogo confirmado

`FreeServersActivity` declara dos fuentes de OpenProxyList, una Base64 y otra
de URI en texto. No existe una capa de cifrado propia en estas fuentes.
La descarga HTTPS real autorizada devolvió **150 perfiles por fuente**:
68 VLESS, 39 VMess, 24 Shadowsocks y 19 Trojan en la captura inicial.
Ambas fuentes contienen la misma lista; no representan 300 servidores distintos.
El contenido es dinámico: una segunda descarga cambió los bytes y volvió a
superar la comparación completa con Java, con 150 perfiles por fuente.

El proveedor `v2ray-tunnel-plus` descarga ambas fuentes y conserva cada una
bajo `catalogs.base64` y `catalogs.raw`. No se identificó un catálogo separado
de usuarios. El resultado incluye el texto completo, SHA-256 de los bytes de
origen, número de registros, URI original y todos sus campos interpretados.
Se preservan orden, duplicados, parámetros repetidos/vacíos/desconocidos y
claves JSON VMess desconocidas con sus tipos originales. Los campos de URI
se exponen sin aplicar valores predeterminados o filtros del dispositivo.

Protocolos recuperados de los lectores Java: `vmess`, `vless`, `trojan`,
`ss`, `socks`, `wireguard`, `hysteria2` y alias `hy2`. Se cubren VMess JSON y
URI, Shadowsocks SIP002 y legado, SOCKS con/sin autenticación, IPv6 y fragmentos
Unicode. Esto lee los perfiles; no comprueba que sus servidores acepten sesiones.

## Uso

Python >=3.10 y `pip install -r requirements.txt`. Al copiar fuera del repositorio,
conservar `codec.py` y la carpeta hermana `HTTP_FenixVPN` con `codec.py` y
`field_names.json`. Solo se reutilizan sus validadores, Base64 y renderizado;
PyCryptodome es una dependencia de ese módulo compartido.

```bash
python server_catalog_decoder.py > catalogos_completos.json
python server_catalog_decoder.py --all > catalogos_completos.json
python server_catalog_decoder.py --base64 > fuente_base64.json
python server_catalog_decoder.py --raw > fuente_texto.json
python server_catalog_decoder.py copia.txt > copia.json
python server_catalog_decoder.py --stdin < copia.txt > copia.json
```

Sin argumentos o con `--all`, descarga ambas fuentes completas. Archivo/stdin y
`run(data: bytes) -> str` funcionan sin red. El transporte combinado es
`spdecode-v2ray-tunnel-plus-catalogs-v1`; `complete:true` exige ambas fuentes.
Si una descarga o un registro falla, se rechaza toda la operación. No se
recortan ni deduplican listas. Cada entrada y el paquete combinado admiten
8 MiB; Cloud mantiene salida de 4 MiB y respuesta HTTP de 6 MiB. Los excesos
producen un error explícito, sin devolver un catálogo incompleto como éxito.

Fuentes primarias fijas verificadas, únicamente en backend:

- `https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_BASE64.txt`
- `https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt`

La app declara además espejos `cdn.jsdelivr.net`, `fastly.jsdelivr.net` y
`gcore.jsdelivr.net`, con ruta `/gh/roosterkid/openproxylist@main/<archivo>`.
Esta integración usa las dos fuentes primarias; no incorpora fallback a esos
espejos. No admite URLs del cliente. El broker comprueba DNS/IP públicos y TLS,
fija las rutas y rechaza redirecciones.

## Evidencia e integración

Se inspeccionaron `FreeServersActivity`, `AngConfigManager.parseConfig`,
`Utils.decode`, `Utils.fixIllegalUrl` y los lectores `*Fmt`. El fragmento URI
reproduce la doble decodificación de Java URI/URLDecoder. A diferencia del mapa
de consulta de la app, la salida conserva también todos los parámetros
repetidos, además del URI exacto. No se registra una extensión de archivo propia
ni una nueva ruta Android: esta entrega integra el catálogo remoto.

El icono es el PNG exacto del lanzador predeterminado, recurso `0x7f100002`,
`res/mipmap-xxxhdpi-v4/ic_launcher.png`, 192×192 y 42800 bytes, sin conversión.
Procedencia y hashes en `manifest.json`. Catálogo público mínimo **18**, con
20 fichas, control administrativo propio y conservación de los switches guardados.

CLI externa real, worker aislado y broker autenticado hacia un worker HTTP
privado real coinciden con los documentos completos del oracle Java independiente.
El DNS nativo de Node devuelve `EAI_AGAIN` en este entorno; las comprobaciones
externas del broker usan transporte controlado y capturas autorizadas, mientras
Python sí descargó las dos fuentes por HTTPS real. No se acredita conectividad
externa de la VPS ni despliegue. No se incluyen APK, respuestas reales o perfiles
descodificados en Git/CI.

Integración en código lista en PR #96; la disponibilidad pública requiere
actualizar la VPS. No se fusiona, despliega ni publica APK o novedades C11.
Ver `TESTING.md`.
