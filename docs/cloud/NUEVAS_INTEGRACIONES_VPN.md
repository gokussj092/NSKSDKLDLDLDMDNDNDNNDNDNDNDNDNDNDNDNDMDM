# Registro de nuevas integraciones VPN

Este registro reúne únicamente las incorporaciones del lote iniciado con
HTTP SocketClay. Se utilizará como fuente para una futura actualización de
novedades cuando el usuario la solicite. No arrastrar funcionalidades de
entregas anteriores ni publicar anuncios automáticamente.

- Rama de trabajo: `feat/austroplus-vpn-13-0-1-decoders`.
- PR: [#96](https://github.com/Gh0stDeveloper/SP-DECODE/pull/96).
- Inicio del lote: 2026-10-20.

## Nuevos Servidores VPN añadidos

- **RJC TUNNEL PRO RJC-6 (6) ✅** — catálogo oficial descargado, descifrado e
  integrado en el PR #96 con autorización externa expresa. HTTP 200 del
  2026-10-22: **41 servidores y 1253 payloads**, versión **22.4**. Asset inicial:
  **46 servidores y 1205 payloads**, versión **15.1**. Ambos documentos completos
  coinciden con JDK independiente, CLI y worker aislado sin salida parcial;
  el CLI `--download` también devuelve la descarga real completa.
- Carpeta `decoders/Python/apps/RJC_TUNNEL_PRO/`, worker `rjc-tunnel-pro`, fuente
  HTTPS fija, control administrativo e icono PNG original. Catálogo mínimo **27**,
  29 fichas. Reutiliza la receta XXTEA de Mx tras confirmarla en este APK, sin
  cambiar lectores anteriores. **3 comprobaciones Python y 24 web aprobadas**;
  sin suites completas. Transporte Node controlado; Python HTTPS/CLI y worker
  aislado reales. Disponible en código, pendiente de actualizar la VPS.
- No se certifica un archivo de perfil ni una API de acceso como feed adicional.
  Sin fusión, despliegue, publicación APK o novedades automáticas; datos reales
  y binarios de análisis excluidos de Git.

- **OnSpace VPN 4.2 (25) ✅** — ambos catálogos oficiales descargados,
  descifrados e integrados en el PR #96 con autorización externa expresa.
  HTTP 200 del 2026-10-22: **164 servidores**, versión **1662**, y **una entrada
  de usuarios**, versión **63**. Ambos JSON y **704 campos no vacíos** coinciden
  con JDK independiente, CLI `--all` por HTTPS real y worker aislado sin salida
  parcial. Los dos assets iniciales también coinciden íntegramente.
- Carpeta `decoders/Python/apps/OnSpace_VPN/`, proveedor `onspace-vpn`, dos URLs
  HTTPS fijas, sobre dual, validación de integridad de ambos documentos y control
  administrativo. Catálogo mínimo **25**, 27 fichas. WebP original conservado y
  PNG con píxeles idénticos. Motor Jireh compartido parametrizado, manteniendo
  sus valores predeterminados y soporte histórico.
- **3 pruebas Python nuevas, 2 regresiones puntuales Jireh y 26 web aprobadas**;
  sin suites completas. Transporte Node/gateway HTTP controlado; proceso aislado
  y HTTPS Python reales. Disponible en código, pendiente de actualizar la VPS.
  Sin fusión, despliegue, APK, publicación de novedades ni certificación de un
  formato de archivo exportado; datos reales excluidos de Git.

- **Mx Tunnel PRO Mx-Build48 (48) ✅** — catálogo oficial descargado, descifrado
  e integrado en el PR #96 con autorización externa expresa. HTTP 200 del
  2026-10-22: **39 servidores y 1467 payloads**, versión **564**. Asset inicial:
  **51 servidores y 1396 payloads**, versión **497**. Ambos JSON completos
  coinciden con JDK independiente, CLI y worker aislado; `--download` también
  validado por HTTPS real. Se mantienen todos los campos, tipos y listas.
- Carpeta `decoders/Python/apps/Mx_Tunnel_PRO/`, proveedor fijo `mx-tunnel-pro`,
  control administrativo, icono PNG original y catálogo mínimo **24**, 26 fichas.
  Reutiliza la primitiva XXTEA histórica con otra clave, preservando el valor
  predeterminado de HX/TRV/4U. **3 pruebas Python, 4 regresiones puntuales TRV/4U
  y 21 web aprobadas**; sin suites
  completas. Transporte Node controlado; sin despliegue ni sesión VPN acreditados.
- Se conservan fuentes reutilizables de inspección APK/APKS, lanzador JADX con
  versión/checksum fijados y lectores de cadenas LSParanoid/Random en
  `scripts/apk_analysis/`. Comprobados con muestras reales; no se suben binarios,
  capturas o datos descifrados. Disponibilidad efectiva tras actualizar la VPS;
  sin fusión, publicación APK o novedades automáticas.

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

- **Focus VPN Cloud 5.0 (59) ✅** — catálogo descargado y abierto con
  autorización externa expresa: **142 servidores**, Version **1081**, **590
  campos cifrados no vacíos**. Documento completo igual al oracle JDK, CLI real
  y worker aislado. Catálogo inicial activo: 1 servidor, Version 1, también igual.
- Carpeta `decoders/Python/apps/Focus_VPN_Cloud/`, bloques Unicode/Base64/
  AES-256-CBC y 12 campos RC4, proveedor `focus-vpn-cloud`, control administrativo,
  icono PNG original y catálogo mínimo **20** (22 fichas). Datos, versiones,
  vacíos y claves desconocidas conservados, sin recortar registros. La fuente de
  anuncios no se anuncia como catálogo de usuarios. No se añade ruta de archivos.
- Comprobación breve solicitada: **3 pruebas Python y 17 web aprobadas**, sin
  suites completas. HTTPS externo por Python y transporte Node controlado.
  Código subido al PR #96; disponibilidad pública tras actualizar la VPS,
  sin despliegue, fusión, APK ni novedades C11 automáticos.

- **FreedomVPN 1.0.29 (125) ✅** — descarga autorizada de **147 servidores**,
  Version **4.4.88**, **1176 campos cifrados procesados**, con igualdad de todo el
  JSON frente al oracle JDK, CLI real y worker aislado. Catálogo inicial: 1
  servidor, Version 1.0.0, ocho campos, también igual. Todos los registros y
  metadatos se conservan; no se fabrica la credencial dinámica del cliente.
- Carpeta `decoders/Python/apps/FreedomVPN/`, XXTEA de delta propio, AES-ECB,
  símbolos/AES-CBC y rotación Java; proveedor `freedom-vpn`, control administrativo,
  icono PNG original y catálogo mínimo **21** (23 fichas). No se añade método
  de archivos ni fuente de usuarios no identificada.
- Comprobación breve solicitada: **3 pruebas Python y 18 web aprobadas**, sin
  suites completas. HTTPS/CLI reales por Python y transporte Node controlado.
  PR #96; disponible públicamente tras actualizar la VPS. Sin despliegue,
  fusión, publicación de APK o novedades automáticos.

- **HTTP Internet Infinito 1.3.9 (139) ✅** — descarga externa autorizada de
  **74 servidores**, Version **1103**, **789 campos procesados (586 no vacíos)**.
  JSON completo igual al oracle JDK, CLI real y worker aislado. El servidor y el
  usuario incorporados en el APK también coinciden completos, Version 1.
- Carpeta `decoders/Python/apps/HTTP_Internet_Infinito/`, WakkoDev/MD5/AES-CBC,
  esquema propio de 29 campos de servidor y siete de usuario, rotación Java
  ROT22, proveedor `http-internet-infinito`, controles e icono PNG original.
  Catálogo mínimo **22** (24 fichas). No se identificó fuente remota de usuarios.
- Comprobación breve: **3 pruebas Python y 19 web aprobadas**, sin suites completas.
  Descarga Python real y transporte Node controlado. PR #96; disponibilidad
  pública tras actualizar la VPS. No se añade ruta de archivos ni se fusiona,
  despliega o publica APK o novedades automáticamente.

- **MegaTunnel 1.17.1 (17) ✅** — catálogo descargado y descifrado realmente,
  con autorización externa: **10 servidores y 124 ajustes**, versión **0.2**,
  **297 campos procesados / 210 no vacíos**. Documento completo igual al oracle
  JDK independiente, descarga Python, CLI real y worker aislado.
- Carpeta `decoders/Python/apps/MegaTunnel/`, AES-256-GCM y 13 campos Base64/XOR,
  proveedor `megatunnel`, controles e icono PNG original. Catálogo mínimo **23**
  (**25 fichas**). Se preservan ambas listas completas, registros dispersos,
  vacíos y metadatos; no se identificó fuente separada de usuarios.
- Comprobación breve: **3 pruebas Python y 20 web aprobadas**, sin suites
  completas. HTTPS real por Python y transporte Node controlado. PR #96;
  disponibilidad pública tras actualizar la VPS. Sin registrar `.meg`,
  fusionar, desplegar o publicar APK/novedades automáticamente.

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

- **ProNeet VPN 27.11 (88) — catálogo remoto pendiente**: lector de ambos
  modos añadido en `decoders/Python/apps/ProNeet_VPN/`, worker aislado
  `proneet-vpn`, icono WebP original y PNG con píxeles idénticos. Assets reales:
  **25 servidores usuario / 23 token**, ambos versión **1.0.0**, **572 campos
  no vacíos** y los dos JSON íntegros iguales a JDK independiente, CLI offline
  y worker (`isPartial:false`). Son recuentos por modo, no 48 servidores distintos.
- Consulta HTTPS autorizada del 2026-10-22: ambas URLs exactas responden
  **HTTP 200 con un único salto de línea**, confirmado también por GitHub.
  El CLI real rechaza ambas sin salida JSON; no hay catálogo remoto descargado
  con éxito. Ficha visible con descarga **desactivada**, catálogo mínimo **26**,
  28 fichas. Habilitación del broker pendiente de documentos oficiales no vacíos.
- **3 comprobaciones Python y 20 web aprobadas**, sin suites completas.
  Datos reales y APK excluidos de Git; no se certifica un formato de perfil ni
  se fusiona, despliega, publica APK o anuncia como descarga remota operativa.

- **EUT VPN 2.4.1 (370) — catálogo remoto pendiente**: lector AES-128-CBC de
  recursos y campos anidados añadido en `decoders/Python/apps/EUT_VPN/`, worker
  aislado `eut-vpn`, icono PNG original y ficha desactivada en catálogo mínimo
  **19** (21 fichas), PR #96. Comprobación breve solicitada: tres pruebas Python
  con vectores independientes JDK, CLI y worker; sin suites completas.
  Consulta HTTPS autorizada: catálogo **401 Missing token**, inicio de sesión
  **403 unsupported_integrity_env**. Falta una sesión oficial aceptada y una
  respuesta real para validar/habilitar la descarga pública; no es falta de
  autorización del usuario. No se anuncian recuentos ni catálogo descargado.
  El lector `.eut` histórico permanece intacto; esta entrega no certifica
  archivos de la versión 2.4.1. CLI preparada para token/cuerpo oficial,
  sin fabricar atestaciones o sesiones ni publicar datos privados.

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

## Actualizaciones de lectores existentes

- **FlexNet V 2.4 (46)**: ampliado el lector en `FlexNet_B42/`, conservando
  v1–v4, sus 30 materiales y las fixtures B42. Admite v5 mínimo 46, v6 con
  clave de setup autorizada y campos SNI/payload FLXFLD con bindings y GCM.
  **22 pruebas específicas aprobadas**, JDK independiente y un campo nativo ARM64.
- **Muestra `free (1).flex` pendiente de clave online**: cabecera reconocida como
  v5 online B46; devuelve `ONLINE_AUTH_REQUIRED`. No se recuperó su contenido
  ni se anuncia descifrado real completo o descarga automática del servidor.
  Es una actualización de script, sin cambio del catálogo Server VPN, despliegue,
  release o novedades automáticas. PR #96; análisis en `docs/FLEXNET_V2_4_B46.md`.

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
