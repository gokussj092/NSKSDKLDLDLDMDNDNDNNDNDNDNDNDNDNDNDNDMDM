# MM Tunnel v1.10.11.1 (45)

Paquete analizado: `co.strongteam.marvsudp`. Lector autónomo de exportaciones
**`.mmt`** y catálogo de servidores. Requiere Python 3.10+, PyCryptodome y
argon2-cffi; funciona sin Android ni bibliotecas del APK.

```bash
python -m pip install -r decoders/Python/apps/MM_Tunnel/requirements.txt
python decoders/Python/apps/MM_Tunnel/file_decoder.py perfil.mmt
python decoders/Python/apps/MM_Tunnel/file_decoder.py - < perfil.mmt
python decoders/Python/apps/MM_Tunnel/server_catalog_decoder.py catalogo-cifrado.json
```

`file_decoder.run(data: bytes) -> str` devuelve `application`, `extension` y
`config` completo. `server_catalog_decoder.run(data: bytes) -> str` devuelve el
catálogo completo, conservando nombres, tipos, campos desconocidos, certificados,
listas y cadenas que contienen JSON. No sustituye el contenido por un resumen.

## Archivos y contraseña

La exportación de `NetworkAdapter.u` serializa un `NetworkList` con Gson y llama
a `Libv2ray.encrypt`, sin parámetro de contraseña. El importador invoca
`parseConfig`, con alternativa `DO`, y lee `Name` y `TunnelType`.

**No se necesita contraseña del usuario para descifrar estos formatos de este
build.** Las constantes y parámetros provienen de su biblioteca Go. No se
deduce esta conclusión para otras versiones. Las credenciales SSH/VPN de la
configuración son contenido y no la contraseña de cifrado.

El lector reconoce exportación cifrada, la alternativa EO/DO y JSON directo que
acepta la aplicación. Los campos internos EO/DO se descifran por separado.
Se verifica cada tag GCM; un campo protegido alterado impide entregar un
resultado parcial. No se solicitan contraseña, clave pública ni HWID.

`.mmt` ya existía en el inventario Ultra/Sandok con otro método histórico.
La nueva ruta reutiliza ese decodificador como alternativa autenticada; el bot
continúa entrando por `ultra.py`. `.mm`, `.md`, `.mdvpn` y otros sufijos conservan
sus rutas. C0 sigue en **240**, C8 en **250**; no es un sufijo nuevo.

## Catálogo y cloud

El asset real `assets/configfile.json` contiene versión **1.01**, **34 servidores**
y **555 redes**. Se abren el documento y sus **3,335 campos cifrados**; sus valores
reales no se incluyen en Git.

El actualizador remoto sí existe: POST fijo a
`https://strongteam.co/api/mmtunnel/`, cuerpo `type=xsandokUpdatex`. La llamada
oficial respondió **HTTP 403** desde el entorno de análisis. El descargador
reproducible está escrito, pero la descarga y el catálogo remoto **no están
validados**. No se fabrica una sesión ni se prueban claves de acceso.

Sin argumento, el CLI de catálogo intenta exclusivamente ese POST fijo. No
acepta URL externa ni redirecciones. `run()` y el puente del worker son offline.
La ficha `mm-tunnel` conserva el PNG original, con `remote:null` y descifrado
remoto desactivado. Server VPN pasa a mínimo **39 / 39 fichas** y conserva sus
switches persistentes. Actualizar el repositorio no despliega estos cambios.

## Texto

No se identificó un prefijo propietario `mmt://` ni una exportación cifrada de
MM distinta del archivo adjunto: el texto de compartir en `NetworkAdapter.u`
solo invita a instalar la app. El APK también contiene los protocolos estándar
VMess, VLESS, Shadowsocks y Trojan de su base V2Ray. Su presencia no prueba una
nueva exportación propietaria. No se añade un alias ni ruta de texto por inferencia.
El CLI permite leer los bytes del archivo mediante stdin.

## Pendientes

- Aportar una exportación `.mmt` real para contrastarla; ahora se validan
  exportaciones sintéticas derivadas del método del APK.
- Obtener una respuesta oficial aceptada antes de habilitar el catálogo remoto.

Ver [ANALYSIS.md](ANALYSIS.md), [TESTING.md](TESTING.md) y
[manifest.json](manifest.json). No se modifica el cliente Android, su diseño,
las novedades C11, una APK ni el despliegue de la VPS.
