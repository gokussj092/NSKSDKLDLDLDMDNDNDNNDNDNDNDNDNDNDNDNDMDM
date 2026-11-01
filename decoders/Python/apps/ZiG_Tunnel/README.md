# ZiG Tunnel — Play 1.0 (1)

Paquete `com.zigtunnel`. La ficha viva de Google Play consultada el2026-11-01
anuncia **1.0**. Se integró el original1.0/build1 cuya firma SHA1 es
`242c140c399ef3321235eded917322e53a7de686`, coincidente con la variante
publicada de ese build. El mirror también ofrece1.2/build3, pero con **otra
firma**: `0e0a9a5a79e7cce8e140fb4b3012fd65077002c2`. No se presenta esa muestra
como la versión de Play ni se certifica compatibilidad con ella.

Catálogo real validado: **2.3,15 servidores,3 HTTPNetworks,1 SSLNetwork**.
GET fijo `https://zimbotunnel.co.zw/default_config.hs`, User-Agent original
**okhttp/5.3.2**. La URL está en el catálogo incluido y en la respuesta remota.
No requiere API key, sesión ni secreto HTTP adicional.

```sh
python -m pip install -r decoders/Python/apps/ZiG_Tunnel/requirements.txt
python decoders/Python/apps/ZiG_Tunnel/server_catalog_decoder.py --download
python decoders/Python/apps/ZiG_Tunnel/server_catalog_decoder.py catalogo.hs
python decoders/Python/apps/ZiG_Tunnel/server_catalog_decoder.py --stdin < catalogo.enc
```

`run(bytes)` y worker son offline; no necesitan APK, SO, Android ni red al
abrir bytes guardados. Conservar HTTP_FenixVPN por sus validadores/render.
La CLI consulta solo la URL fija, con TLS y límites; rechaza redirecciones,
HTML, cuerpos vacíos y respuestas distintas de200. No usa el asset para
ocultar un error de descarga. El broker fija DNS público/TLS y mantiene los
controles existentes de sesión, cuota y disponibilidad individual.

## Receta recuperada del Java original

`AbstractC1257r4.T`: Base64 → `AbstractC0818iL.NethWs3Dev` XXTEA de palabras
little-endian, clave UTF8 **4669** rellenada con ceros hasta16bytes,
**delta772515655**, longitud original en la última palabra → UTF8 → restar
**4669 dos veces a cada unidad UTF16 Java**, con wrap16bits. No usar el delta
XXTEA estándar ni restar a puntos de código Unicode completos.

La misma receta abre el sobre exterior y cada campo protegido confirmado:

| Contexto | Campos |
| --- | --- |
| Raíz | config_url, account_api, upload_get_api, upload_post_api, AppConfPass, Ovpn_Cert |
| Servers | ServerIP, ServerCloudFront, ServerHTTP, ProxyHost, Username, Password, ovpnCertificate |
| Listas de redes | NetworkPayload, NetworkFrontQuery, NetworkBackQuery, SquidProxy, SSLSNI, SSLPayload |

Conservar **HTTPNetworks, DirectNetworks, DNSNetworks, UDPNetworks y SSLNetworks**
cuando estén presentes, sin crear las ausentes ni aplanar/descartar secciones.
JSONsettings, metadatos, tipos, desconocidos y placeholders se mantienen.
No interpretar todo Base64 como cifrado. `cloud_get_api/cloud_post_api` del
original son metadatos no consumidos por las rutas confirmadas del build;
se preservan como desconocidos. No se consultan APIs de cuentas o subida.

Fallo de un campo conocido invalida la salida completa. XXTEA no tiene MAC:
las comprobaciones de longitud/UTF8/JSON no equivalen a autenticidad.
No se reproduce la selección de servidores ni las sustituciones de conexión.

## Alcance de la integración

Actualizador OpenVPNClient.E → AsyncTaskC0193Lm → cliente OkHttp sin cabeceras
personalizadas; C0699g4.f abre la respuesta. Base incorporada por
`R.raw.default_config` → `res/raw/default_config.hs`.
Es un catálogo de aplicación completo; no se infiere un formato de perfil
exportado, un nuevo prefijo de texto ni una extensión global por ese nombre.
No se añade/reasigna .hs o .zig en C8. Se mantienen **255 formatos /240 C0**.
No writer/exportador certificado, Android físico ni conexión VPN probados.

Ficha `zig-tunnel`, broker/worker/gateway/control e icono PNG original exacto
500×500,186687bytes. Fuente59 /57 fichas al cerrar esta segunda integración.
No se despliega, fusiona ni compila APK. [Pruebas](TESTING.md),
[manifest](manifest.json) y [continuidad](../../../../docs/cloud/ENAA_ZIG_TUNNEL_HANDOFF_2026_11_01.md).
