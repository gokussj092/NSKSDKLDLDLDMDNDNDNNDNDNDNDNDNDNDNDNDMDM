# Actualización 2026-11-09 — build15

Catálogo actual: nueva fuente AustroTunVPN.json y esquema de campos en minúsculas, con compatibilidad build13. Paridad completa Java/Python/worker:5 servidores y174 ajustes. Evidencia y herramientas: [expediente build15](../../../../analysis/xyz.tekidoer.austroplus.vpn/15/RESULTS.md). Archivos build15 independientes no certificados.

## Documento histórico build13

# AustroPlus VPN 13.0.1

Paquete `xyz.tekidoer.austroplus.vpn`, versionCode **13**. Lectores separados
para archivos `.aro` actuales y catálogo remoto; no necesitan el APK en ejecución.

## Uso

Python 3.10 o posterior. El catálogo usa únicamente biblioteca estándar;
los archivos requieren PyCryptodome:

```bash
python -m pip install -r requirements.txt
python file_decoder.py perfil.aro
python file_decoder.py < perfil.aro
python server_catalog_decoder.py > catalogo.json
python server_catalog_decoder.py copia-cifrada.json > catalogo.json
python server_catalog_decoder.py --stdin < copia-cifrada.json
```

**Sin argumentos, el lector del catálogo descarga la URL original fija y
muestra todo el JSON descifrado.** Un archivo local o `--stdin` seleccionan
lectura offline. `run(data: bytes) -> str` nunca accede a la red.

Mantener `codec.py` junto a los dos lectores. En el repositorio se reutiliza
la primitiva estándar XXTEA de `decoders/Python/ec.py`, sin modificarla; el ZIP
incluye su copia exacta como `ec.py`. No hacen falta Java ni bibliotecas Android.

## Archivos `.aro` de esta versión

El exportador `ExportActivity.p()` crea un objeto raíz `CONFIG`, cifra su JSON
mediante `o8.b()` y escribe Base64. El importador `MainActivity.B()` utiliza
`o8.a()`. El sobre es:

```text
Base64(nonce de 12 bytes | AES-256-GCM | etiqueta de 16 bytes)
```

Se verifica siempre la etiqueta GCM. No hay un prefijo de enlace propietario
identificado: el archivo y stdin contienen ese Base64 directamente. No se
registra un esquema inventado ni se modifica el dispatcher global de textos.

Los campos `CFGMessage`, `MyPass`, `Payload`, `SNIHost`, `BUGHost`, `DNSHost`,
`V2RAYLink`, `UDPIP`, `UDPPorts`, `UDPObfs`, `UDPAuth`, `ProxySet` y `Server`
llevan **dos capas de Base64 Android DEFAULT**, con posibles saltos de línea.
Los vacíos permanecen vacíos. `Server`, si está presente, contiene texto JSON
con campos Base64/XOR; el resultado conserva su tipo de cadena JSON.

Se preservan raíz, campos desconocidos, tipos, versión, contraseña de
importación, HWID, caducidad y restricciones de root/red/instalador. `MyPass`
es un campo del contenido, no la clave GCM. No se aplican transformaciones de
conexión, sustituciones de `[host]` ni selección aleatoria de servidores.

El formato histórico `.aro` del repositorio usa Base64 y desplazamiento de
bytes. Permanece intacto en su motor anterior. Cloud identifica su documento
JSON `CONFIG` completo **antes** de seleccionar la ruta; no lo intenta como
alternativa después de un fallo AES-GCM. El lector de esta carpeta es exclusivo
del formato actual autenticado. No se cambiaron `aro.py` ni `ec.py`.

## Catálogo remoto

URL original recuperada del catálogo inicial:

```text
https://raw.githubusercontent.com/SpkHexX/HexX/refs/heads/main/AustroPlusVPN.json
```

El sobre usa **Base64 → XXTEA estándar**, delta `0x9e3779b9`, palabras
little-endian y longitud final. La clave del APK se trunca/rellena a 16 bytes,
como hace `m83.i()`. No se usa la variante XXTEA de `ys.i()`: el consumidor
real `sa.a()` / actualizador `v8.run()` llama a **`m83.j()`**.

`url_updater` y los campos protegidos de servidores y tweaks usan Base64 y
XOR repetido con la constante `BaseZh` (`ys.h()` / `MainActivity.Y()`). Se
descifran solo las ubicaciones comprobadas en los consumidores Java; nombres,
puertos, modo, flags, metadatos y campos desconocidos conservan sus tipos.

| Fuente verificada, 19 de octubre de 2026 | Servidores | Tweaks |
| --- | ---: | ---: |
| Catálogo inicial incrustado en `ej.c` | 1 | 1 |
| Descarga remota real | 6 | 198 |

Se verificó el **JSON completo** de ambas fuentes contra las funciones Java
originales: 6 / 503 campos de XOR, incluidos vacíos. El remoto mantiene la misma
URL de actualización. El script imprime todos los registros y no sustituye
la descarga por la pequeña muestra local del APK.

El APK guarda las actualizaciones cifradas en la columna `DATA` de
`system.db`, no en un formato adicional de exportación. El lector de catálogo
puede abrir una copia de ese texto cifrado; no abre directamente SQLite.

## Icono, integración y límites

Icono original completo: `AustroPlus_VPN.png`, extraído de
`res/mipmap-xxxhdpi-v4/ic_launcher.png`, **192×192 y 16607 bytes**. Es el PNG
completo del lanzador de mayor densidad; el recurso adaptativo XML no se
presenta erróneamente como PNG. Sin ampliación artificial ni cambio de marca.
Se conserva idéntico en la carpeta y el backend. La política general permite
originales por encima de antiguos límites de peso.

ID Cloud fijo `austroplus-vpn`, catálogo público **versión mínima 8**, broker
HTTPS con DNS/IP pública anclada y ruta fija. No acepta URL desde el cliente ni
sigue automáticamente `url_updater` del documento. API/proveedores continúan
desactivados por defecto. El inventario C0 conserva 240 extensiones y C8 246;
`.aro` ya estaba registrada. Sin cambios Android ni de diseño web.

Límites: archivo de entrada 5 MiB, catálogo 8 MiB, salida CLI 8 MiB y profundidad
JSON 64. Cloud conserva sus presupuestos generales, incluida salida máxima de
4 MiB. Descarga de 25 segundos, sin redirecciones ni compresión. Un error de
etiqueta, campo o estructura termina sin entregar JSON parcial.

Se analizaron el exportador/importador y perfiles sintéticos cifrados con el
Java original. **No se recibió una exportación `.aro` real independiente**;
`exporterCertified` permanece `false`. Los catálogos local y remoto sí son
muestras reales verificadas. Detalles en [TESTING.md](TESTING.md).

Rama nueva `feat/austroplus-vpn-13-0-1-decoders`, creada desde `main`
`e6cbb5926372aa6b7d36105802bf366a2138c98e`. Sin fusión, despliegue ni publicación APK.
