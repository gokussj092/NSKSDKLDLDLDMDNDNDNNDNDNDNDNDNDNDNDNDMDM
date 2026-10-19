# Robust Tunnel VPN — isvsoft 16.4.7

Aplicación `app.robusttunnelvpn.nishat.build`, versión `isvsoft 16.4.7`,
versionCode 16. Un único lector, `server_catalog_decoder.py`, descarga y
descifra el catálogo real o procesa una copia local. **No necesita el APK,
Java, bibliotecas nativas, dependencias pip ni credenciales de usuario.**

| Ruta identificada | Comportamiento |
|---|---|
| Actualización desde la URL fija original | Descarga y descifra el catálogo completo |
| Importación de archivo, solicitud 100 | Lee el mismo catálogo cifrado; no exige extensión |
| `assets/conf` | Catálogo inicial incluido en el APK; lectura offline de sus bytes |
| Archivo privado `conf` / `cachedJsonConfig` | Copia actualizada / caché JSON de la app |
| `assets/custom` / `CustomTweaks` | Almacén local de ajustes personalizados; no es una exportación independiente |

No se identificó una exportación autónoma de perfiles, una extensión propia
de perfiles ni un esquema de texto como `robust://`. Por ello no se crea
`file_decoder.py` ni se añaden extensiones inventadas al router de archivos.
La importación de archivos existente se atiende con el lector de catálogo.

## Uso

Python 3.10 o superior, únicamente biblioteca estándar:

```bash
# Descarga la URL original y escribe el JSON completo en stdout.
python server_catalog_decoder.py > catalogo.json

# Copia cifrada guardada previamente; no hace conexiones.
python server_catalog_decoder.py copia_catalogo > catalogo.json
python server_catalog_decoder.py --stdin < copia_catalogo > catalogo.json
```

El script se puede copiar y ejecutar solo, desde cualquier carpeta. El nombre
del archivo local no determina el formato. No admite una URL arbitraria como
destino de descarga. Los errores sanitizados aparecen en stderr, con código
de salida 1 y sin datos descifrados en stdout.

```python
from pathlib import Path
from decoders.Python.apps.Robust_Tunnel_VPN.server_catalog_decoder import run

resultado_json = run(Path("copia_catalogo").read_bytes())
```

`run(data: bytes) -> str` siempre funciona offline. La descarga queda separada
en `download()` y en el broker Cloud. No se usan ni prueban los endpoints de
autenticación, registro de dispositivos o conexión VPN de la aplicación.

## Catálogo real y copia local

| Muestra validada el 2026-10-19 | Servidores | Ajustes (`Tweaks`) | Certificados |
|---|---:|---:|---:|
| Catálogo inicial `assets/conf` | 74 | 434 | 1 |
| Catálogo remoto original | 151 | 1187 | 6 |

Son colecciones diferentes: los 1187 ajustes no se cuentan como servidores.
Las cantidades remotas pueden cambiar. Se devuelve todo el objeto JSON,
incluidos `ReleaseNotes`, valores predeterminados, servidores de distintos
protocolos, ajustes, certificados, metadatos y propiedades desconocidas.

## Formato y evidencia

`MainActivity.tYaLO0l` obtiene la URL de `XEz4WHn.NlQ97AI()` y hace un GET.
`MainActivity.e0I7BeC` descifra la respuesta con
`androidx.lifecycle.utils.c.decryptBase64StringToString` y `ConfigsKey`.
`onActivityResult(100)` lee el archivo seleccionado y lo envía a esa misma
rutina, usando `GET_CONTENT`, MIME `*/*`, sin comprobación de extensión.
`sk9841I.updateCachedJsonConfig` carga el archivo privado `conf` o el asset
inicial y almacena el JSON de catálogo.

El sobre es **Base64 → XXTEA personalizado → JSON UTF-8**. Utiliza palabras
little endian, clave truncada/rellenada a 16 bytes, longitud original al final
y delta **`0x9E130714`** (`-1642920172` en Java). No se usa el delta estándar
de XXTEA ni el motor RENZ de la aplicación anterior.

Los campos protegidos utilizan **hexadecimal → texto Base64 → XXTEA de la
misma variante → UTF-8**. Se corresponden con `c.goD` / `utils.a.d` y usan los
primeros 16 bytes del material devuelto por `isvJNI.certificate()`.
La clave del sobre se obtiene de `ConfigsKey` en el bootstrap de la app;
ambas son constantes compartidas del formato, no contraseñas de usuarios.
El bootstrap nativo/AES solo se resolvió durante el análisis: no es necesario
extraerlo ni ejecutar el APK cada vez que se decodifica un catálogo.

Se descifran los campos confirmados de servidores, credenciales, proxies,
payloads, V2Ray, Hysteria y DNSTT. `ServerFlag`, `TweakIcon`, puertos globales,
certificados y otras propiedades sin cifrado se conservan. Un código como
`DE` no se interpreta como ciphertext por parecer hexadecimal. El contenido
V2Ray/UDP que sea una cadena se conserva como cadena, incluidos sus saltos de
línea; no se modifica la estructura ni se transforma en otra configuración.

La implementación de esta variante está en el único script de la app; no se
copian ni cambian los motores históricos. Un campo protegido corrupto provoca
error completo; no se presenta como descifrado satisfactorio parcial.

## Cloud e icono

- ID fijo `robust-tunnel`, registrado en `catalog_vpn_bridge.py` y `engine.py`.
- Broker HTTPS fijo con IP pública anclada, TLS, límites y query original
  inmutable en redirecciones. El cliente envía únicamente el ID del proveedor.
- Nombre, icono y disponibilidad en el catálogo público; URL y claves quedan
  exclusivamente en los módulos backend, fuera del APK cliente.
- Catálogo público versión mínima **4**, también por defecto en Compose.
  Una instalación con versión explícita debe elevarla a un entero mayor que
  el anterior y al menos 4 al actualizar. El CLI QA conserva la progresión.
- `CLOUD_SERVER_VPN_ENABLED` permanece desactivado por defecto. Este cambio
  no despliega, no altera Android ni la interfaz administrativa.

`Robust_Tunnel_VPN.png` es el icono original de 96 × 96, extraído del split
xhdpi y copiado sin modificar. Su checksum y el recurso de origen constan en
`manifest.json`; coincide con el PNG servido por Cloud.

## Límites y compatibilidad

Entrada/salida local: 8 MiB; profundidad JSON: 64. Cloud conserva su límite de
salida de 4 MiB y los presupuestos existentes de descarga/worker. Solo se
certifica la muestra de app analizada: no se afirma compatibilidad con otras
apps isvsoft ni versiones futuras con cambios de claves o algoritmo.

La paridad de ambos catálogos se comprobó con el algoritmo Java original,
incluidos 1094 campos internos locales y 2644 remotos. No se suministró una
exportación de archivo independiente: se validan los bytes reales de catálogo
que consume la ruta de importación, sin afirmar una prueba de UI en Android.
No se verifica si las cuentas o servidores VPN permiten conectarse.

Ver `TESTING.md` para las muestras, hashes, controles y pendientes.
