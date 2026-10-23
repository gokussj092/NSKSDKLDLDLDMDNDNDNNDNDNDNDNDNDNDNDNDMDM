# Registro de nuevas integraciones VPN

Este registro reúne únicamente las incorporaciones del lote iniciado con
HTTP SocketClay. Se utilizará como fuente para una futura actualización de
novedades cuando el usuario la solicite. No arrastrar funcionalidades de
entregas anteriores ni publicar anuncios automáticamente.

- Rama de trabajo: `feat/austroplus-vpn-13-0-1-decoders`.
- PR: [#96](https://github.com/Gh0stDeveloper/SP-DECODE/pull/96).
- Inicio del lote: 2026-10-20.

## Nuevos Servidores VPN añadidos

- **7NET VPN 5.6 (56) ✅** — catálogo público oficial integrado en PR #96:
  **76 servidores / 619 redes-payloads**, Version **40.19**, HTTP 200,
  758848 bytes. **6025 campos / 4750 no vacíos** y todo el JSON iguales a
  JDK independiente; CLI HTTPS/stdin y worker aislado entregan **502968 bytes**,
  `isPartial:false`. Catálogo inicial: **92 / 634**, Version **1.0**,
  **6347 campos / 4982 no vacíos**, también igual íntegro.
- Carpeta `decoders/Python/apps/SevenNET_VPN/`, ID fijo `7net-vpn`, PNG original,
  control individual y URL exacta sin redirecciones. Catálogo mínimo **33**,
  **35 fichas**; preserva switches y versión persistente. Reutiliza RENZ y
  corrige el recorte CBC en seis campos por muestra, verificado con las
  primitivas ARM64 originales (**9 casos por fuente / 18 ejecuciones**).
  `.7net` y aliases conservan su ruta; no se certifica una exportación real
  independiente que no se aportó. **12 Python / 54 web aprobadas**, sin suites
  completas. Herramientas y recuperación guardadas en `scripts/apk_analysis/`
  y referencias sintéticas en `tests/golden/sevennet*`. Pendiente desplegar VPS;
  no se fusiona, publica APK ni se modifican novedades C11 automáticamente.

- **Xhypher Tunnel Pro 43 (43) ✅** — catálogo oficial descargado e integrado
  en PR #96: **57 servidores / 1161 redes-payloads**, Version **2.665**,
  HTTP 200, 1386712 bytes. **10055 campos procesados / 7363 no vacíos** y
  todo el JSON coinciden con JDK independiente, CLI HTTPS/stdin y worker
  aislado (`isPartial:false`, 858366 bytes). Catálogo inicial: **1 / 1**,
  Version **1.0.0**, también igual íntegro.
- Carpeta `decoders/Python/apps/Xhypher_Tunnel_Pro/`, proveedor fijo
  `xhypher-tunnel-pro`, control administrativo, fuente HTTPS exacta y PNG
  original sin conversión. Catálogo mínimo **32**, **34 fichas**.
  Reutiliza primitivas RENZ confirmadas en este SO; añade el portador invisible
  de credenciales y conserva ceros legítimos de ciphertext en tres campos.
  La ruta canónica `.xhypher` y aliases históricos se mantienen; no se registra
  extensión nueva ni se certifica una exportación real no aportada.
- **4 pruebas nuevas, 4 regresiones RENZ y 46 web aprobadas**, sin suites
  completas. **10 casos de primitivas ARM64 originales aprobados**, incluidos
  los tres streams Threefish afectados. Solo memoria/cadenas modeladas;
  sin ejecución Android/JNI o sesión VPN. HTTPS Python/CLI/worker reales;
  transporte Node controlado.
- Herramienta LSParanoid ampliada con campo/método renombrados, conservando
  defaults: 1987 literales, 81 archivos, 2252 cadenas de inventario. Fuentes
  y referencias guardadas; sin APK/SO/catálogos reales/credenciales de servicio
  en Git. Disponible en código, pendiente de VPS; sin merge, despliegue,
  APK ni actualización automática de C11.

- **TurboMX VPN 143.1.26 (168) ✅** — ambos catálogos oficiales descargados,
  descifrados e integrados en PR #96 con autorización externa expresa.
  HTTP 200 del 2026-10-22: **268 servidores**, versión **18**, y **una entrada
  de usuarios**, versión **3**; 2900 campos procesados / 2189 no vacíos.
  Assets: **240 / 1**, versión **3 / 3**. Los cuatro documentos completos
  coinciden con KDF/AAD originales de TurboMX, libsodium y JDK; CLI HTTPS
  `--all`, stdin fuera del repo y worker aislado también coinciden íntegramente.
- Carpeta `decoders/Python/apps/TurboMX_VPN/`, proveedor `turbomx-vpn`, dos fuentes
  fijas, sobre dual, control e icono original. Catálogo mínimo **30**, 32 fichas.
  Reutiliza SV5C v2 con release **143**, firma, clave y contexto propios;
  SuperFlash conserva release 157 y supera sus regresiones y par real/worker.
- **3 pruebas TurboMX, 3 regresiones SuperFlash y 31 web aprobadas**; sin suites
  completas. Herramientas ELF/JNI/ARM64 reutilizadas y layouts conocidos por hash
  guardados en Git. Transporte Node controlado; HTTPS/CLI y worker reales.
  Disponible en código, pendiente de VPS. Sin fusión, despliegue, APK, novedades
  automáticas o formato de archivo nuevo; binarios y cuentas fuera de Git.

- **SuperFlash VPN 184.0.1 (184) ✅** — ambos catálogos oficiales descargados,
  descifrados e integrados en el PR #96 con autorización externa expresa.
  HTTP 200 del 2026-10-22: **268 servidores**, versión **27**, y **una entrada
  de usuarios**, versión **5**; 2900 campos procesados / 2189 no vacíos.
  Todos los registros, firmas y tags se abren; ambos documentos completos y
  los dos assets SV5C coinciden con KDF/AAD nativos originales, libsodium y JDK.
  CLI HTTPS `--all`, stdin fuera del repo y worker aislado coinciden íntegramente.
- Carpeta `decoders/Python/apps/SuperFlash_VPN/`, proveedor `superflash-vpn`, dos
  fuentes fijas, sobre dual, controles y PNG original. Catálogo mínimo **29**,
  31 fichas. SV5C v2/Ed25519/XChaCha20-Poly1305 más campos AES-CBC/ROT5;
  los metadatos visibles por sí solos no cuentan como descifrado completo.
- **3 comprobaciones Python y 30 web aprobadas**, sin suites completas.
  Herramientas nuevas ELF/JNI y ARM64 conservadas en `scripts/apk_analysis/`,
  referencias y vectores sintéticos en `tests/golden/`. Python HTTPS/CLI y worker
  reales; transporte Node controlado. Disponible en código, pendiente de VPS.
  Sin fusión, despliegue, APK o novedades automáticas; binarios y cuentas fuera
  de Git. No se registra un formato de archivo exportado nuevo.

- **RMP TUNNEL PRO RMP-5 (5) ✅** — catálogo oficial descargado, descifrado e
  integrado en el PR #96 con autorización externa expresa. HTTP 200 del
  2026-10-22: **40 servidores y 1250 payloads**, versión **9.9**. Asset inicial:
  **40 servidores y 1211 payloads**, versión **3.8**. Ambos documentos completos
  coinciden con JDK independiente, CLI y worker aislado sin salida parcial;
  el CLI `--download` también devuelve la descarga real completa.
- Carpeta `decoders/Python/apps/RMP_TUNNEL_PRO/`, worker `rmp-tunnel-pro`, fuente
  HTTPS fija, control administrativo e icono PNG original. Catálogo mínimo **28**,
  30 fichas. La receta XXTEA se confirmó en este APK y reutiliza Mx sin alterar
  lectores anteriores. **3 comprobaciones Python y 25 web aprobadas**;
  sin suites completas. Transporte Node controlado; Python HTTPS/CLI y worker
  aislado reales. Disponible en código, pendiente de actualizar la VPS.
- No se registra un perfil exportado ni una API de acceso como feed adicional.
  Sin fusión, despliegue, publicación APK o novedades automáticas; datos reales
  y binarios de análisis excluidos de Git.

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

- **1FTunnel 0.6.99 (125) ✅ — `.1ftnl` y cuatro prefijos de texto**:
  muestra real aportada autenticada AES-256-GCM y CFG1 completo de **1995 bytes**,
  JSON íntegro igual a JDK, CLI y worker aislado de archivo/texto, sin recorte.
  KDF HKDF-SHA256 y contraseñas UTF-16BE confirmadas con ARM64 original.
- Carpeta `decoders/Python/apps/OneFTunnel/`, API Python/bot, ruta Cloud,
  credenciales por stdin y detección Android para servidor. Contenedor v1–v3 y
  CFG1 v1–v5, SSH/inyección/DNS/Xray completos. **9 Python / 13 Node aprobadas**,
  15 vectores sintéticos JDK y **32 comparaciones KDF ARM64** incluyendo la
  muestra real. Worker HTTP local autenticado verificado; sin suites completas.
- Herramientas `oneftunnel_native_oracle.py` / `oneftunnel_verify.py` y guía de
  recuperación conservadas. Catálogo **no identificado, pendiente**; sin nuevo
  proveedor/ficha Server VPN. C0 sigue 240, C8 efectivo 248. Disponible en código
  del PR #96, pendiente de VPS/cliente actualizado; sin despliegue, fusión, APK
  o novedades C11 automáticos. Datos reales y binarios fuera de Git.

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

- **AM TUNNEL LITE VPN — AM (63): pendiente de catálogo**. El núcleo Java está
  protegido con LIAPP; **todavía no se ha abierto íntegramente `pdrv2.json`**.
  El enlace extraído del APK agotó el tiempo de espera y no se validó su
  respuesta. **No anunciar como servidor operativo ni como integración completa.**
  Se incorpora solo la ficha y PNG original, `remote:null`, catálogo mínimo
  **34 / 36 fichas**. Sin ruta de worker/broker ni extensión nueva.
- En `decoders/Python/apps/AM_TUNNEL_LITE_VPN/` queda un auxiliar de campos
  PUtils hexadecimal/XOR/UTF-8 modificado, **8 vectores JDK / XOR ARM64 iguales**,
  **4 Python / 43 web aprobadas**. No equivalen a paridad del catálogo.
  Herramientas versionadas: extractor de primera capa nativa
  `scripts/apk_analysis/liapp_wrapper.py`, oracles/generador y guía de
  recuperación. `ANALYSIS.md` conserva los hashes y el punto de continuación.
  El DEX/lector protegido aún no se recuperó; no se suben datos reales ni
  se despliega, fusiona, publica APK o modifica C11.
  Continuación: validación local de paquete/SHA-1 identificada y metadatos
  LIAPP de **213 bytes** recuperados por Python y checkpoint ARM64 original
  con contexto modelado, iguales byte por byte. Herramientas, generador y
  **3 pruebas nuevas / 7 Python aprobadas** conservados. Esto no abre el
  catálogo, no demuestra identidad HTTP y no cambia la ficha ni su versión.


- **UT Loop Pro VPN 22.10.26 (65) — catálogo remoto pendiente**: lector
  RSA/SHA-256 + AES-256-GCM de actualizaciones firmadas y copias locales en
  `decoders/Python/apps/UT_Loop_Pro_VPN/`, worker fijo `ut-loop-pro-vpn`.
  El catálogo inicial real se autentica: **un servidor / un tweak, versión 1.0**;
  todo el JSON coincide con JDK independiente, CLI fuera del repo y proceso
  aislado (`isPartial:false`). Auxiliar de banners SSH GCM con ambos certificados
  y XXTEA heredado, validado con vectores sintéticos JDK; no es un perfil exportado.
- La consulta autorizada del endpoint oficial devolvió **HTTP 200, HTML,
  195 bytes, Site Unavailable**; sin catálogo firmado remoto ni sesión OTA
  aceptada. El APK usa Play Integrity/acceso OTA y un entitlement premium
  separado. No se inventan accesos, credenciales, registros premium ni feeds
  de usuarios. Chequeos adicionales de acceso bloqueados por revisión
  automática; no se reintentaron y no se usan como evidencia.
- **4 pruebas Python y 38 web aprobadas**; sin suites completas. CLI/worker
  reales para el catálogo incluido, transporte remoto controlado para las
  solicitudes oficiales. Ficha e icono PNG original exacto conservados con
  `remote:null`, catálogo mínimo **31**, **33 fichas**; sin allowlist ni
  activación administrativa remota hasta validar la respuesta oficial.
- Herramienta reutilizable `scripts/apk_analysis/stringfog_strings.py` guardada:
  2438 llamadas literales en 71 archivos. README/TESTING/manifest/vectores
  incluidos. Sin formato de archivo nuevo, APK/datos reales en Git, fusión,
  despliegue, publicación APK o novedades automáticas.

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

- **NPV Tunnel 124.0.37 (577)**: ampliado el Python canónico `.npvs` con
  passphrase v5 (PBKDF2/ChaCha20-Poly1305). Muestra real completa: una
  configuración, **16 registros autenticados / nueve campos `npvs1:`**,
  JSON entero igual a JDK, CLI fuera del repo y worker aislado.
- Public-key: punto P-256 válido y fingerprint coincidente, pero los dos
  adjuntos normal/public-key son idénticos NPVS v6 recipient; **pendiente la
  privada del dispositivo y una exportación normal distinta**. Se informa
  `PRIVATE_KEY_REQUIRED`, sin anunciar descifrado v6. Se conserva v5 app-key,
  sus tablas y el lector v4. **16 Python / 15 Node aprobadas**, sin suites
  completas. Herramientas y oracles guardados; documentación
  `docs/NPVS_PROTECTED_FILES.md`. Rutas backend listas, pendiente desplegar;
  sin Android/UI, formato nuevo, Server VPN/C11, fusión o APK automáticos.

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
