# Registro de nuevas integraciones VPN

Este registro reúne únicamente las incorporaciones del lote iniciado con
HTTP SocketClay. Se utilizará como fuente para una futura actualización de
novedades cuando el usuario la solicite. No arrastrar funcionalidades de
entregas anteriores ni publicar anuncios automáticamente.

- Rama de trabajo: `feat/austroplus-vpn-13-0-1-decoders`.
- PR: [#96](https://github.com/Gh0stDeveloper/SP-DECODE/pull/96).
- Inicio del lote: 2026-10-20.

## Nuevos Servidores VPN añadidos

- **HTTP SocketClay 3.4.0 ✅** — catálogo de servidores y usuarios descargado,
  descifrado e integrado en código en el PR #96. Validación del 2026-10-21:
  **86 servidores y 2 entradas de usuarios**, versiones `107` / `10`; 673 campos
  cifrados no vacíos y ambos JSON completos coinciden con el oracle Java.
- Carpeta: `decoders/Python/apps/HTTP_SocketClay/`; icono original, lectores,
  manifiesto, pruebas y documentación propios. Worker `http-socketclay` aislado.
- Broker descarga ambas fuentes HTTPS fijas verificadas y devuelve los documentos
  íntegros bajo `catalogs.servers` / `catalogs.users`, manteniendo sus versiones.
  Ninguna fuente se omite silenciosamente. No se incluyen respuestas o credenciales
  reales en Git ni se ejecuta el contenido de los resultados.
- Tarjeta remota habilitada en código; mínimo de Server VPN **15** y controles
  administrativos de activación. La huella persistente incorpora la revisión del
  catálogo para invalidar la disponibilidad anterior sin borrar `switches.json`.
- **50 pruebas Python y 152 pruebas Node aprobadas localmente**; CLI con descarga
  real, proceso aislado y flujo autenticado al worker HTTP real verificados.
  El transporte externo nativo Node se comprobó con pruebas controladas porque
  el DNS de este entorno devuelve `EAI_AGAIN`; no se afirma despliegue en la VPS.
- Autorización externa explícita recibida del usuario. El bloqueo de revisión
  anterior queda resuelto. Disponibilidad pública efectiva tras actualizar la VPS;
  sin fusión, despliegue ni anuncio C11 automáticos.

- **HTTP Wakko 4.9 (40) ✅** — catálogo de servidores y usuarios descargado,
  descifrado e integrado en el PR #96 con autorización externa expresa.
  **91 servidores y 2 entradas de usuarios**, versiones `116` / `8`, y **735
  campos cifrados no vacíos**; ambos documentos completos coinciden con el
  oracle Java independiente. Incluye slots BHTTP de servidores tipo 5.
- Carpeta `decoders/Python/apps/HTTP_Wakko/`: lector, esquema de 29 campos de
  servidor/siete de usuarios, icono original WebP y PNG sin pérdida, manifiesto,
  pruebas y documentación. Worker `http-wakko`, descarga dual de fuentes HTTPS
  fijas, controles administrativos y catálogo mínimo **16**.
- **66 pruebas Python y 162 pruebas Node aprobadas** en esta entrega, incluidas
  regresiones SocketClay/Fenix/Jireh. CLI real y flujo autenticado con capturas
  completas hacia worker HTTP privado real verificados; la conectividad externa
  Node usa pruebas controladas por `EAI_AGAIN` del entorno. Disponibilidad pública
  tras actualizar la VPS. No se fusiona, despliega ni publica C11 automáticamente.
- No se identificó formato de perfil exportado/importado en Wakko 4.9; no se
  registra `.sks` u otro método de archivos únicamente por compartir helpers.

- **V2ray Tunnel Plus 10.0.0 (4000010) ✅** — suscripciones públicas Base64 y
  URI en texto descargadas e integradas en el PR #96 con autorización externa
  expresa. Validación 2026-10-22: **150 perfiles por fuente**, misma lista
  representada de dos formas (no 300 distintos). Captura inicial: 68 VLESS,
  39 VMess, 24 Shadowsocks y 19 Trojan. Ambos documentos completos coinciden
  con Java independiente; nueva captura CLI tras actualizarse la lista también.
- Carpeta `decoders/Python/apps/V2ray_Tunnel_Plus/`, lector sin cifrado propio,
  ocho esquemas URI, orden/duplicados/campos conservados e icono PNG original.
  Worker `v2ray-tunnel-plus`, dos fuentes HTTPS primarias fijas, controles y
  catálogo mínimo **18** (20 fichas). No se identificó catálogo separado de
  usuarios ni se añade una extensión propia o ruta Android de archivos.
- **89 pruebas Python y 173 Node aprobadas localmente**. CLI con HTTPS real,
  proceso aislado y flujo autenticado a worker HTTP privado real verificados
  con ambos documentos completos. DNS externo Node controlado por `EAI_AGAIN`
  del entorno; no se afirma prueba externa desde la VPS. Disponibilidad pública
  tras actualizar la VPS, sin fusión, despliegue o novedades automáticos.

## Nuevos métodos de archivos, textos o enlaces añadidos

- **HTTP SocketClay 3.4.0 ✅ — archivos `.sks`**: lector Python y ruta Cloud
  compartida con Fenix/Jireh. GCM y DES comprobados con el importador del APK y
  vectores Java sintéticos; exportación real independiente no proporcionada.
  Carpeta: `decoders/Python/apps/HTTP_SocketClay/`, PR #96. No se añade otra
  extensión ni se modifica Android. Su catálogo remoto también está integrado
  según la sección anterior.

- **TunelGuard VPN 12.8 (128) ✅ — archivos `.tgv`**: lector Python, worker
  C8 y detección Cloud Android incorporados. AES-CBC nativo, Modified UTF-8 y
  16 campos doble Base64 comprobados con JDK y ejecución ARM64; 32 campos del
  servidor interior incluidos. Metadatos de contraseña/HWID/caducidad intactos.
  No se proporcionó exportación real independiente ni se certifica writer.
  Carpeta `decoders/Python/apps/TunelGuard_VPN/`, PR #96.
- Entrega TunelGuard: **140 pruebas Python y 163 Node aprobadas localmente**;
  petición autenticada al worker HTTP real con resultado completo verificada.
  Icono original WebP y PNG sin pérdida, ficha añadida al catálogo mínimo **17**.
  Reconocer `.tgv` requiere cliente actualizado; no se publica APK automáticamente.

## Integraciones pendientes

- **TunelGuard VPN 12.8 — catálogo remoto pendiente**: el lector STGCM2.TG
  abre el documento inicial entero (1 servidor / 1 ajuste, versión 0.1,
  paridad Java), pero la URL original devuelve **HTTP 404**, confirmado por
  Python HTTPS y las APIs de GitHub con autorización del usuario. La ficha
  permanece **desactivada**; no se anuncia descarga remota operativa ni una
  lista de usuarios inexistente. Habilitar únicamente tras validar una respuesta
  oficial autenticada. No es un bloqueo de permisos.

Los catálogos de SocketClay y Wakko mantienen su validación anterior.
Persisten únicamente la comprobación del servicio desde la VPS tras un despliegue
solicitado y los límites de certificación `.sks` documentados en `TESTING.md`.

## Cómo completar el registro

Al terminar cada integración:

1. Mover su nombre a la sección confirmada que corresponda, con ✅.
2. Registrar versión de app, alcance confirmado, carpeta, pruebas realizadas,
   limitaciones pendientes y commit/PR. No incluir credenciales, respuestas
   privadas, URLs internas ni datos descifrados.
3. Distinguir integración en código de disponibilidad tras despliegue.
   Si falta una comprobación necesaria, conservarla como pendiente.
4. No generar ni publicar todavía `whats-new.json`. Cuando el usuario pida
   preparar las novedades, utilizar solo las incorporaciones confirmadas
   de este lote y respetar las versiones y cachés de cada sistema.

Leer también [la guía de integración](SERVER_VPN_NEXT_CHAT_GUIDE.md) y
[el procedimiento de actualización de catálogos y novedades](CATALOGS_UPDATE_RUNBOOK.md).
Server VPN y What's New tienen versiones independientes. Una modificación
de este registro, por sí sola, no cambia ninguno de esos catálogos.
