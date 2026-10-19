# My Tunnel Proxy 2.3

Aplicación `com.mytunnelproxy.vpn`, versión 2.3 (23), analizada a partir de
`My Tunnel Proxy_2.3.zip`. Los lectores **no necesitan el APK** para funcionar.
Conservan el JSON completo y descifran sus campos sin conectar a servidores VPN.

| Entrada comprobada | Lector | Resultado |
|---|---|---|
| Exportación `.mtp` o texto `mytunnelproxy://…` | `file_decoder.py` | Perfil JSON, con todas sus propiedades |
| Catálogo remoto fijo de la app | `server_catalog_decoder.py`, sin argumentos | Descarga y JSON completo de servidores/redes |
| Copia cifrada del catálogo `.js`/`.rj` | `server_catalog_decoder.py archivo.rj` | El mismo JSON; operación offline |
| Referencia `mytunnel://…` | `file_decoder.py --reference` | Identificador del archivo Cloud, sin descargarlo |

La descarga validada el 19 de octubre de 2026 contenía **44 servidores y 601
redes**, no 645 servidores. Es un catálogo dinámico: las cantidades pueden cambiar.
No se publica su contenido ni sus credenciales.

## Uso

Desde la raíz del repositorio, con Python 3.10 o superior:

```bash
python -m pip install pycryptodome==3.23.0
python decoders/Python/apps/My_Tunnel_Proxy/file_decoder.py ejemplo.mtp > perfil.json
python decoders/Python/apps/My_Tunnel_Proxy/file_decoder.py < enlace.txt
python decoders/Python/apps/My_Tunnel_Proxy/server_catalog_decoder.py > catalogo.json
python decoders/Python/apps/My_Tunnel_Proxy/server_catalog_decoder.py copia.rj > catalogo.json
python decoders/Python/apps/My_Tunnel_Proxy/file_decoder.py --reference < referencia.txt
```

El resultado se imprime en stdout; los errores sanitizados se envían a stderr y
el proceso devuelve código 1. Los lectores funcionan desde otro directorio si
se conserva la estructura del repositorio y su dependencia `renz.py`.
Ambas entradas exponen `run(data: bytes) -> str`, siempre offline.
Solo el CLI de catálogo, sin archivo, hace la descarga.

## Formatos y evidencia

`el0.onClick` añade `.mtp`, abre `CREATE_DOCUMENT` con MIME heredado
`application/x-7net` y solicitud 1999. `MyTunnelProxyMain.onActivityResult`
escribe `mytunnelproxy://` seguido de un objeto JSON cifrado con tipo 0.
`MyTunnelProxyMain.O` y `ll0` importan el mismo esquema. El MIME no cambia la
extensión real ni convierte los archivos en perfiles de otra aplicación.

La solicitud 1996 acepta `.js`/`.rj` para actualizar el catálogo. El método
`Q` descarga el catálogo de la URL fija incorporada en el lector. La respuesta
es Base64 cifrado, no un objeto JSON HTTP directo. El JSON descifrado contiene
`Version`, `Servers`, `Networks`, credenciales y metadatos adicionales.
`c.x` carga una copia inicial desde `R.raw.g` o una actualización local `a.rlb`;
los lectores aceptan los bytes del catálogo, sin requerir extraer otra vez el APK.

La capa nativa proviene de `libovpn3.so`, no de un archivo de servidores local.
Las constantes compartidas del formato se extraen de esa biblioteca y no son
contraseñas de usuarios. Se reutilizan las primitivas de `decoders/Python/renz.py`
sin modificar los algoritmos, claves ni rutas de las aplicaciones anteriores.

| Tipo nativo | Operación de descifrado |
|---|---|
| 0: sobre, nombres, puertos y metadatos seleccionados | Base64 → AES-128-CBC/PKCS#7, SHA-256 del material → XXTEA personalizado; sin desplazamiento de bytes |
| 1: host, SNI, payload y configuración V2Ray | Base64 → Threefish-256, tweak `(índice, índice × 192)` → AES-128-CBC; claves HKDF-SHA256 |
| 2: usuario y contraseña | Unicode invisible U+200B/U+200C/U+200D → intercambio de bits/XOR → XXTEA → AES-256-CBC con IV prefijado; PBKDF2-HMAC-SHA256, 100000 iteraciones |

En tipo 1, el relleno de Threefish tiene 0 o 16 bytes. El código original
elimina todos los ceros finales y puede perder un byte legítimo del ciphertext
AES. El lector comprueba las dos longitudes posibles con PKCS#7 y UTF-8 y exige
una única solución. Este caso ocurrió en un campo SNI del catálogo real y está
cubierto por un vector sintético independiente.

Se descifran únicamente los nombres de campos confirmados en la app; se
preservan valores vacíos, booleanos, números, nulos y propiedades desconocidas.
No se reinterpretan cadenas Base64 arbitrarias ni JSON contenido dentro de una
cadena de configuración V2Ray. Un campo cifrado reconocido que falle provoca
error completo, nunca una respuesta presentada como descifrado parcial.

## Alcance y limitaciones

- La paridad del catálogo completo se comprobó con las primitivas ARM64
  originales. Los archivos `.mtp` se verificaron con vectores sintéticos
  generados por esas primitivas; falta una exportación real entregada por el usuario.
- `mytunnel://` referencia un archivo `config/…` del repositorio Cloud usado por
  la aplicación; no contiene el perfil. Se recupera el identificador offline.
  La descarga autenticada de ese archivo no está implementada y no se emplean
  credenciales incorporadas en la aplicación. Un perfil obtenido legítimamente
  se procesa como `.mtp`/`mytunnelproxy://`.
- Se conservan `Lock`, vencimiento, PIN y mensajes tal como vienen. El lector
  no modifica la app, las restricciones del perfil ni las cuentas del servicio.
- `.ovpn` es configuración OpenVPN ordinaria y no recibe otro descifrador.
- Límite local: entrada/salida 8 MiB y profundidad JSON 64. Cloud conserva sus
  límites existentes: salida 4 MiB, texto 250000 caracteres y tiempo de worker.
  No se prometen versiones de la app posteriores a 2.3.

## Integración Cloud

ID fijo `my-tunnel-proxy`; `.mtp` en la ampliación C8 del router, sin modificar
las 240 rutas congeladas C0. `mytunnelproxy://` tiene ruta de texto explícita.
Las extensiones genéricas `.js`/`.rj` solo se admiten en el lector de catálogo
local, para evitar secuestrar formatos de otras aplicaciones.

El broker HTTPS del backend fija host, consulta original, IP pública validada,
TLS, redirecciones y presupuesto de descarga. La app cliente envía únicamente
el ID; no se aceptan URLs arbitrarias. La metadata pública muestra nombre,
ID, checksum del icono y disponibilidad; no publica endpoints ni claves.

El catálogo de presentación sube a versión **3**. En una instalación que ya
fije `CLOUD_SERVER_VPN_CATALOG_VERSION`, al actualizar debe usarse un valor
**mayor que el anterior y al menos 3**. `qa start/services/stop` conserva la
progresión monotónica y eleva versiones antiguas. El interruptor
`CLOUD_SERVER_VPN_ENABLED` continúa desactivado por defecto. No se despliega,
no se cambia Android ni la interfaz administrativa en esta entrega.

`My_Tunnel_Proxy.png` es el icono original de 512 × 512, copiado sin modificar
desde `res/h/bx.png`. Su SHA-256 está en `manifest.json` y coincide con
`cloud/web/public/server-vpn-icons/my-tunnel-proxy.png`.
Las verificaciones detalladas y las limitaciones de muestra están en `TESTING.md`.
