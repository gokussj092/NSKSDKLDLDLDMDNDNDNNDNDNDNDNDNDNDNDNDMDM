# ALFAISAL Tunnel+ — build39

Paquete `app.ovpninject5.vpn`, versión **Version -39WH-wake /39**, vigente en
Google Play y en el APK comprobado el 2026-11-01. Catálogo remoto validado:
**HTTP200, 4.0.20, 4 servidores, 51 Networks y 103 SSLNetworks**.

## Uso

```sh
python -m pip install -r decoders/Python/apps/ALFAISAL_Tunnel_Plus/requirements.txt
python decoders/Python/apps/ALFAISAL_Tunnel_Plus/server_catalog_decoder.py catalogo.enc
python decoders/Python/apps/ALFAISAL_Tunnel_Plus/server_catalog_decoder.py --stdin < catalogo.enc
python decoders/Python/apps/ALFAISAL_Tunnel_Plus/server_catalog_decoder.py --download
```

`--download` requiere **los tres secretos reales** en el entorno del backend:
`SPDECODE_ALFAISAL_API_KEY`, `SPDECODE_ALFAISAL_SIGNING_KEY` y
`SPDECODE_ALFAISAL_DEVICE_UUID`. Los dos primeros proceden del mismo APK; el
tercero es una instalación de prueba propia registrada una sola vez mediante
el flujo normal de la app. No se registra una instalación por petición.
Faltando cualquiera, la descarga y el botón remoto quedan deshabilitados.
Archivo privado duradero y provisión en el [handoff](../../../../docs/cloud/ALFAISAL_TUNNEL_PLUS_HANDOFF_2026_11_01.md).
No pasar secretos como argumentos ni incluirlos en Git o salida del script.

## Petición original completa

1. GET fijo `https://panel.alfaisalvpn.com/api/app_settings.php`, query
   `json_client_capability=2` y `device_uuid` de la instalación del backend.
2. Solo continuar si `json_requires_integrity` es explícitamente false.
   No se fabrica un token si cambia la política del servidor.
3. POST fijo `https://panel.alfaisalvpn.com/api/protected_json.php` con JSON
   compacto en este orden: device_uuid, integrity_token vacío,
   integrity_request_id vacío, integrity_request_hash vacío,
   integrity_operation="json_update", json_client_capability=2,
   json_direct_requested=1.
4. Content-Type `application/json; charset=utf-8`, Accept application/json,
   Cache-Control no-cache, X-API-KEY, X-TIMESTAMP Unix en segundos,
   X-NONCE aleatorio de16 bytes/32 hex y X-SIGNATURE hex minúscula.
   Firma HMAC-SHA256 con la clave como **texto UTF8**, sobre los bytes exactos
   `timestamp.nonce.body`. No interpretar la clave como hex ni reserializar
   el cuerpo después de firmarlo.

Código original: `OpenVPNClient.J1/W7`, `bb.a.d`, `g3.y0`, `g3.f1.i/g3.x0`.
La primera petición sin registrar recibió403; la instalación propia se registró
por el flujo normal y la petición completa obtuvo200. No se utilizan identidades
ajenas. El broker no accede al registro ni a otras operaciones del panel.
No redirecciones, URLs elegidas por el cliente ni reintento del mismo nonce.
DNS público y TLS verificado; respuestas y errores acotados y saneados.

## Descifrado y contrato

`gb.o` aporta la contraseña de formato; SHA256 UTF8 produce la clave AES256.
Base64 → AES-CBC con IV cero16 → PKCS7 → UTF8. Sobre exterior estricto JSON;
campos de servidor Username, Password, SSHUsername, SSHPassword; raíz Username,
Password; en **ambas** listas Networks y SSLNetworks, Payload, SNIHost y
ProxySettings.Squid. Preservar las tres listas y todos sus registros.

`gb.m$a.b` devuelve el campo original ante GeneralSecurityException de CBC.
La muestra real tiene **tres ProxySettings.Squid antiguos** con ese resultado;
se conservan exactamente como la app. No son tres registros descartados ni
claves adivinadas. Se rechazan Base64 malformado, tipos incompatibles y JSON
incompleto; los errores CBC del sobre exterior siempre rechazan el documento.
Nombres, IP/hosts/puertos, FrontQuery, tipos de túnel, desconocidos y placeholders
se conservan; no se elige un perfil ni se sustituyen variables.

Bootstrap `res/0k.js`: versión0.0.0, 1 servidor, 0 Networks, 1 SSLNetwork.
Se valida por separado y nunca sustituye una descarga remota fallida.
El motor no introduce extensión/texto nuevo; el recurso `.js` es un catálogo
incluido, no un formato público. No se certifica un exportador de perfiles.

Integración `alfaisal-tunnel-plus`: ficha e icono PNG original, switch persistente,
broker firmado en web, worker offline allowlisted y validación C3 de las tres
listas. Fuente **59 /55 fichas**, aún sin despliegue. Las credenciales solo
llegan a web, no al worker ni al catálogo público. Véanse [pruebas](TESTING.md)
y [manifest](manifest.json).
