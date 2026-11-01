# MM Tunnel v1.10.30.2 (47)

Paquete `co.strongteam.marvsudp`. Catálogo remoto y lector Cloud de perfiles
**`.mmt`**, sin Android ni bibliotecas del APK en ejecución. Python3.10+,
PyCryptodome y argon2-cffi. Se conserva la compatibilidad del build45 y la
alternativa histórica Ultra/Sandok.

## Descarga remota corregida

El actualizador nativo `ConfigUpdate -> Libv2ray.cu -> CU` del build47 envía:

- POST fijo a `https://strongteam.co/api/mmtunnel/`.
- Formulario exacto **`hash=xsandokUpdatex`**.
- `Content-Type: application/x-www-form-urlencoded`.
- User-Agent original por defecto **`Go-http-client/1.1`**.

El script anterior enviaba `type=xsandokUpdatex`; esa petición no representa
la receta del build47 y seguía fallando. Se reutiliza la constante del
actualizador, ya presente en el proyecto; no se calcula una huella nueva ni se
requiere otra identidad, sesión, API key o secreto privado de servidor.

Descarga real **HTTP200**, **822713 bytes**, versión **2.46**, **38 servidores /
557 redes**; documento completo con **3399 campos protegidos distintos**,
contrastado con libsodium Argon2id y Java/JCA AES-GCM. El asset incluido sigue
siendo1.01,34/555; no se usa como sustituto de la respuesta remota.

```bash
python -m pip install -r decoders/Python/apps/MM_Tunnel/requirements.txt
# Sin argumento: descarga original real y descifrado completo.
python decoders/Python/apps/MM_Tunnel/server_catalog_decoder.py
# Archivo cifrado guardado o stdin: operación offline.
python decoders/Python/apps/MM_Tunnel/server_catalog_decoder.py catalogo.enc
python decoders/Python/apps/MM_Tunnel/server_catalog_decoder.py - < catalogo.enc
python decoders/Python/apps/MM_Tunnel/file_decoder.py perfil.mmt
```

`run(data: bytes) -> str` es offline. La CLI y el broker usan la misma receta
fija; no admiten URLs del cliente ni redirecciones. El broker mantiene TLS,
validación DNS/IP, límites y controles persistentes. Ficha `mm-tunnel` conectada
a su proveedor y al worker existente; C12 permite desactivarla individualmente.
57 fichas, revisión fuente59, C0 congelado240/C8 efectivo255. El despliegue y
la actualización de la versión efectiva del catálogo quedan separados.

## Cifrado, integridad y metadatos

Argon2id v19, t3,m16384KiB,p1,key32; AES256-GCM con salt16,nonce12,tag16 y
AAD=salt. Exportación/respuesta remota: clave de formato de32 bytes e inserción
de una letra ASCII en índice3 del Base64. EO/DO usa su clave de21 bytes para el
asset y campos internos. Las claves verificadas no cambiaron entre45 y47.

Solo se abren los campos confirmados del nivel raíz y las entradas de Servers
y Networks; se conservan listas enteras, campos desconocidos, tipos, cadenas
JSON y placeholders. **Info se muestra directamente y URI es un indicador**;
no se descifran por parecer Base64. Tampoco los homónimos de campos protegidos
en metadatos desconocidos. Todos los tags GCM de campos protegidos deben ser
válidos; un error impide entregar un resultado parcial.

## Archivos y alcance

`NetworkAdapter.v` del build47 mantiene `Gson -> Libv2ray.encrypt -> .mmt`,
MIME `application/x-mmt`. No hay contraseña del usuario en la receta de cifrado.
`file_decoder.run` entrega application/extension/config completo. Se mantienen
los sufijos históricos `.mm`, `.md`, `.mdvpn` y el bot por Ultra/Sandok.

Las exportaciones sintéticas se contrastaron con una referencia independiente
y el worker; **sigue pendiente una exportación .mmt real y probar su importación
en Android**. No se certifica un escritor nuevo ni un esquema `mmt://`.

Ver [ANALYSIS.md](ANALYSIS.md), [TESTING.md](TESTING.md), [manifest.json](manifest.json)
y [handoff](../../../../docs/cloud/MM_TUNNEL_REINTEGRACION_2026_11_01.md).
El código está integrado en la rama de trabajo; no se ha fusionado ni desplegado.
