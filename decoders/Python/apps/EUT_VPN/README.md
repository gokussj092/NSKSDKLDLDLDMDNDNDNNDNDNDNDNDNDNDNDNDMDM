# EUT VPN 2.4.1

Paquete `xyz.eutvpn.app`, build **370**. Lector de catálogo incorporado en el
PR #96, rama `feat/austroplus-vpn-13-0-1-decoders`.

`server_catalog_decoder.py` abre copias autorizadas del catálogo de recursos.
Reproduce `sza.b`: AES-128-CBC/PKCS7, clave recuperada truncada a 16 caracteres
y codificada ISO-8859-1, sobre `Base64(ciphertext):Base64(IV16)`. Abre el campo
`data` de cada recurso y los campos cifrados anidados. Conserva todas las
entradas de `SERVER`, `PAYLOAD`, metadatos, versiones y secciones adicionales;
no aplica filtros ni límites de servidores de la UI. Una entrada inválida
rechaza el documento, sin devolver una lista parcialmente descodificada.

## Uso

Python >=3.10 y `pip install -r requirements.txt`. Conservar la carpeta hermana
`HTTP_FenixVPN`, con `codec.py` y `field_names.json`, para validación y renderizado.

```bash
python server_catalog_decoder.py copia_recursos.json > catalogo.json
python server_catalog_decoder.py --stdin < copia_recursos.json > catalogo.json
python server_catalog_decoder.py --download > catalogo.json
```

Archivo/stdin y `run(data: bytes) -> str` funcionan sin red. La descarga usa
únicamente POST a `https://api.eutvpn.com/v5/android/client/get-all-resources`.
Requiere `EUT_VPN_ACCESS_TOKEN` y `EUT_VPN_REQUEST_JSON`, procedentes de una
sesión oficial válida y su cuerpo JSON correspondiente. No genera identidades,
atestaciones o sesiones ni renueva tokens automáticamente. No acepta URLs
arbitrarias ni redirecciones. Los valores de sesión no se guardan en Git.
Entrada y salida del lector: 8 MiB, profundidad 64; exceso produce error.
El worker conserva sus presupuestos generales de salida/transporte.

## Estado remoto y Cloud

Consulta externa autorizada el 2026-10-22: el catálogo devuelve **401 Missing
token**. `init-session` con cuerpo vacío devuelve **403 unsupported_integrity_env**.
El APK envía un Bearer y parámetros de `NativeKeys.getParams`; su flujo de inicio
de sesión integra verificación de integridad. No se recibió una sesión válida
ni un catálogo real, por lo que no se anuncia descarga operativa o recuentos.

Worker aislado `eut-vpn` registrado. Ficha con icono original añadida al catálogo
mínimo **19** (21 fichas), con descarga **desactivada**. No se habilita el broker
público hasta validar una respuesta oficial completa y definir la gestión de
sesión en backend. La variable de sesión descrita arriba pertenece a la CLI;
no activa la ficha por sí sola.

Icono PNG original incluido en `base.apk:assets/appicon-store.png`, 512×512,
sin conversiones. No se modifica el lector histórico `decoders/Python/eut.py`
ni las rutas `.eut` existentes. Validación breve en `TESTING.md`; no se ejecutan
suites completas ni se despliega, fusiona o publica APK en esta entrega.
