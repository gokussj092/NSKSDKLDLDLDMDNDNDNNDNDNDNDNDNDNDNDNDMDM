# CATNET VPN — catálogo de servidores Cloud

Build analizada: `net.catnet.vpn`, 1.2.5/code27 de APKPure, identidad comprobada
en el manifiesto. No se certifica última build ni equivalencia de firma Play.

Se integra **solo la respuesta completa de `mobile/public/servers`**: 6 servidores
en la muestra real. Es JSON UTF-8 sin cifrado observado en esta ruta; conserva
todos los campos, metadatos, defaults y tipos, incluidos los objetos anidados.
No se aplican heurísticas Base64/hex ni se extrae una lista reducida de conexiones.

El descargador ejecuta primero `app-update` con `app_key=pussy_vpn`, build27 y
las cabeceras originales recuperadas de DEX. Un UUID nuevo identifica la
operación; se mantiene entre sus dos GET. `pussy_vpn` es un identificador de
cliente estático incluido en la APK, no una contraseña de cuenta. No necesita
secretos externos. Se permite continuar únicamente con `integrity_required:false`;
si pasa a requerir verificación, falta el campo o hay mantenimiento, se detiene.
No se fabrica Play Integrity ni sesión. TLS normal, destinos fijos, sin redirects.

```sh
python decoders/Python/apps/CATNET_VPN/server_catalog_decoder.py > catalogo.json
python decoders/Python/apps/CATNET_VPN/server_catalog_decoder.py catalogo.json
python decoders/Python/apps/CATNET_VPN/server_catalog_decoder.py --stdin < catalogo.json
```

`run(bytes)` es offline; el worker no hace red. No se añaden formatos de
archivo/texto/exportación. Las rutas separadas `payloads` y `xray_payloads` de
xjdev.net devolvieron HTTP200 con HTML «Site Unavailable» y **no están soportadas**.
La respuesta de servidores no se presenta como snapshot combinado de las tres
fuentes ni incluye payloads inventados. No se usan cuentas ni rutas privadas.

Icono Android PNG original192×192, sin recodificar. Piso72/66 fichas/256 formatos,
preservando versiones VPS superiores y switches. Solo Cloud; sin Android ni
despliegue. Node real aquí `REMOTE_NETWORK_DENIED`; replay real con HTTP simulado
aprobado, comprobación Node en VPS pendiente.

[Expediente](../../../../analysis/net.catnet.vpn/27/MANIFEST.json),
[reproducción](../../../../analysis/net.catnet.vpn/27/REPRODUCE.md),
[resultados](../../../../analysis/net.catnet.vpn/27/RESULTS.md).
