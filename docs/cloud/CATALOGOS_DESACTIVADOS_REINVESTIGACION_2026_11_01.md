# Catálogos desactivados: reinvestigación e integración obligatorias

Fecha: **2026-11-01**. Directiva del propietario de SP-DECODE para retomar las
integraciones remotas incompletas y evitar repetirlas en próximas aplicaciones.
Cuenta Goku; rama `fix/http-jireh-current-method`. Inventario actualizado tras completar MM Tunnel build47, sobre el commit
**64ea621350d0a0695b5203869de38a243c8ab57c**: revisión fuente **59**,
**57 fichas**, **9 con remote:null**. Integración en código; no desplegada.

## Directiva de continuidad

**Las aplicaciones con catálogo remoto desactivado por integración pendiente
deben investigarse nuevamente desde su aplicación original.** No basta conservar
el motivo de bloqueo de una investigación antigua, incorporar el icono o abrir
el catálogo incluido en el APK. Hay que completar el método, la petición, sus
datos de acceso y su conexión con el backend, y demostrar una descarga real.

Aplicar el mismo criterio usado en **VIP Snipher Pro, IZPH VPN PRO y ALFAISAL
Tunnel+**: seguir el actualizador activo, incorporar todos los datos que utiliza,
descargar correctamente y comparar el documento completo con una referencia
independiente. Esta exigencia también rige para cada nueva app.

Un GET anónimo que devuelve 404, un 403, una página HTML con 200 o un timeout
no demuestran por sí solos que el servicio esté caído o que el método no pueda
integrarse. Primero hay que contrastar lo que envía la app y lo que envía el
script. Si faltan cabeceras, claves, firmas, registro o sesión, la integración
remota sigue pendiente aunque su lector offline funcione.

La lista siguiente incluye **las 9 fichas con `remote:null` en el código**.
Es un inventario de integración, no una consulta al VPS ni una nueva prueba de
sus endpoints. Los resultados HTTP citados son históricos; no describen su
estado actual ni prueban la causa de cada fallo. Los originales indicados son
los últimos documentados, no una afirmación de que hoy sean los más recientes.

## Lista de aplicaciones que deben retomarse

| Aplicación e ID | Último original documentado | Evidencia del pendiente | Trabajo que debe completarse |
| --- | --- | --- | --- |
| **HA Tunnel Plus** (`ha-tunnel-plus`) | 1.7.1 /76; `com.hatunnel.plus` | Recursos, constantes y URL del actualizador protegidos por DexProtector. El lector histórico `.hat` no acredita el catálogo actual. | Recuperar la ruta activa de ResourceUpdater y sus recursos/claves; reproducir la petición y abrir todas sus secciones. [Evidencia](../../decoders/Python/apps/HA_Tunnel_Plus/README.md). |
| **CREEB VPN** (`creeb-vpn`) | 50.0 /50; `com.creebtunnel.vpn` | Incluido1.0.0, 1 servidor/1 ajuste validado. Flujo Play Integrity observado; GET devolvió HTML y POST sin token405. No se probó una atestación válida. | Reconstruir el flujo oficial de actualización y sus datos de autorización; validar respuesta completa. Es distinta de CREEB INJECTOR. [Evidencia](../../decoders/Python/apps/CREEB_VPN/README.md). |
| **AM TUNNEL LITE VPN** (`am-tunnel-lite-vpn`) | AM /63; `app.vpn.amtunnellite` | Auxiliar de campos XOR y metadatos LIAPP comprobados; el sobre de `pdrv2.json` no está abierto. URL extraída agotó timeout, sin status HTTP. | Recuperar las clases consumidoras y el método exterior, confirmar fuente y petición, abrir todo el catálogo y completar worker/broker. Una primitiva de campos no basta. [Evidencia](../../decoders/Python/apps/AM_TUNNEL_LITE_VPN/README.md). |
| **UT Loop Pro VPN** (`ut-loop-pro-vpn`) | 22.10.26 /65; `loop.uchetechs.vpn.pro` | Catálogo inicial y verificación RSA/GCM implementados. OTA devolvió200 HTML; falta acceso OTA válido y respuesta firmada real. | Completar la gestión oficial de X-Api-Key, X-Ota-Access y X-Ota-Iid. Tratar premium por separado, solo con entitlement válido; mantener firma y GCM obligatorios. [Evidencia](../../decoders/Python/apps/UT_Loop_Pro_VPN/README.md). |
| **ProNeet VPN** (`proneet-vpn`) | 27.11 /88; `com.proneet.vpn` | Ambos modos incluidos validados; las dos URLs remotas devolvieron200 con un solo LF el 2026-10-22. | Volver al actualizador de la versión vigente y confirmar ambas fuentes. Descargar y validar **modo usuario y modo token** completos, conservando sus versiones por separado. [Evidencia](../../decoders/Python/apps/ProNeet_VPN/README.md). |
| **EUT VPN** (`eut-vpn`) | 2.4.1 /370; `xyz.eutvpn.app` | Lector de recursos implementado. Catálogo sin sesión devolvió401 Missing token; init-session vacío403 unsupported_integrity_env. No hubo sesión válida ni catálogo real. | Completar petición, parámetros NativeKeys y sesión oficial válida; definir provisión, vigencia y renovación autorizada en backend antes de integrar el broker. Las variables actuales de CLI no habilitan la ficha. [Evidencia](../../decoders/Python/apps/EUT_VPN/README.md). |
| **TunelGuard VPN** (`tunelguard-vpn`) | 12.8 /128; `tunnel.guard.vpn` | Incluido0.1, 1 servidor/1 ajuste y lector STGCM2.TG validados. La fuente GitHub extraída devolvió404 en la investigación previa. | Verificar versión y actualizador actuales, URL exacta y posible autorización requerida; integrar la fuente que la app utiliza y demostrar descarga y descifrado completos. [Evidencia](../../decoders/Python/apps/TunelGuard_VPN/README.md). |
| **DTunnel Mod** (`dtunnel-mod`) | 4.2.5 /9; `com.dtunnel.v2ray.pro`, nombre interno Fastiver Vpn Pro | **El script sí descargó 46 perfiles reales el 2026-10-18**, con paridad JCA. La ficha sigue desactivada por faltar el acceso privado y su integración en el broker público. | Revalidar el original y la descarga; provisionar privadamente el identificador autorizado, conectar broker/worker/control y probar el flujo Cloud completo. El actualizador normal usa `credentials.json.user_id` en `dtunnel-token`, no el campo `token`. [Evidencia](../DTUNNELMOD_4_2_5.md). |
| **Royal Tunnel VPN** (`royal-tunnel`) | 7.0 /7; `kd.app.royaltunnelplus` | Incluido27 servidores/100 tweaks validado. Fuente externa devolvió200 con 195 bytes de HTML el 2026-10-19, sin catálogo válido. | Revisar actualizador y datos de petición de la app vigente; validar respuesta real, todas las capas y colecciones, y añadir el broker/control que falta. [Evidencia](../../decoders/Python/apps/Royal_Tunnel_VPN/README.md). |

Todas permanecen **pendientes de revisión remota** hasta cerrar su caso. En
DTunnel Mod el pendiente principal documentado es de integración Cloud y
provisión privada, no de haber demostrado ya el descifrado del catálogo.
En HA y AM también falta recuperar parte del propio método. En las demás,
el soporte offline existente se conserva como evidencia y punto de partida;
no debe presentarse como una integración remota terminada.

## Historial de casos resueltos en código

**MM Tunnel v1.10.30.2/build47 — 2026-11-01:** se corrigió la clave del
formulario del actualizador: el script enviaba type y el original vigente usa
hash. Descarga real HTTP200,822713 bytes,2.46,38 servidores/557 redes,3399
campos protegidos distintos; JSON entero igual a referencia independiente,
CLI y worker. Broker/C12/ficha/gateway conectados. Constante del actualizador
reutilizada, sin secreto privado adicional.29 Python/129 Node aprobadas;
transportes Node simulados, despliegue pendiente. [Evidencia y recuperación](MM_TUNNEL_REINTEGRACION_2026_11_01.md).

Por instrucción del propietario, detenerse después de MM y reportar; la cola
solicitada restante es CREEB VPN,AM TUNNEL LITE VPN,UT Loop Pro VPN,
ProNeet VPN,EUT VPN,TunelGuard VPN, en ese orden, una por entrega.

## Procedimiento obligatorio para cada caso y para nuevas apps

1. **Verificar el original vigente.** Paquete, versión, build, certificado y
   SHA256 del APK. Contrastar la ficha actual con el binario y los consumidores;
   no dar por vigente una URL o clave de un build antiguo. Guardar el original
   y su recuperación fuera de los temporales que pueden limpiarse.
2. **Seguir la actualización completa.** Recuperar URL final, método, query,
   cuerpo y orden/bytes de serialización, Content-Type, User-Agent y demás
   cabeceras. Examinar metadata, selección de modo, registro, sesión, nonce,
   timestamp, firma, Authorization, API keys y cookies cuando la app los use.
   No confundir una ruta de descarga de APK con un catálogo de servidores.
3. **Incorporar los datos necesarios.** Reutilizar los datos del actualizador
   del mismo original exclusivamente para su fuente y operación autorizadas.
   Las constantes de formato pueden estar en código; credenciales e identidades
   privadas deben provisionarse como secretos del backend. Por instrucción del
   propietario, sus valores **no se suben a GitHub**, tampoco a fixtures o logs.
   Documentar nombres, consumidor, origen verificado, vigencia y recuperación.
   Una variable vacía, un valor ficticio o un TODO no completan esta parte.
4. **Resolver los pasos previos reales.** Reutilizar la instalación propia ya
   registrada cuando corresponda; no crear una nueva por descarga. Si se exige
   sesión, integridad o suscripción, implementar el flujo oficial autorizado y
   respetar su política. No fabricar tokens/atestaciones, usar identidades
   ajenas ni omitir verificaciones. Si falta acceso legítimo, registrar ese
   requisito concreto y mantener el caso pendiente, sin declarar soporte remoto.
5. **Ejecutar el script con descarga real.** Registrar fecha, HTTP, tamaño,
   SHA256, versión, secciones y recuentos sin publicar valores privados.
   HTTP 200 debe contener el catálogo esperado, no HTML, JSON de error o bytes
   vacíos. La CLI debe funcionar con la petición completa y datos reales.
   No sustituir el fallo remoto por un asset antiguo ni por un mock exitoso.
6. **Comparar todo el resultado.** Contrastar sobre exterior y cada familia
   de campos con la implementación original o una referencia independiente.
   Conservar todas las listas, modos, servidores, redes, SSL, usuarios y demás
   secciones presentes; nombres, tipos, desconocidos y placeholders intactos.
   No truncar, filtrar por la selección de la UI ni descifrar cualquier Base64
   por heurística. Reproducir solo los fallbacks confirmados de la app y
   documentar sus recuentos, como los tres proxies antiguos de ALFAISAL.
7. **Completar la integración de backend.** Broker con fuente fija, TLS/DNS y
   redirecciones restringidos, receta de petición completa y secretos solo en
   el servicio que descarga. Worker offline aislado, contrato de resultado
   íntegro, ficha/icono original y control individual persistente. Comprobar
   que faltando acceso se informa un error claro y no se entrega éxito parcial.
   Planificar caducidad/renovación y evitar reutilizar un nonce al reintentar.
8. **Probar y guardar la evidencia.** CLI fuera del checkout, worker, gateway
   con sesión/cuota, conservación íntegra, errores y límites; pruebas sintéticas
   sin datos reales, más evidencia separada de descarga real. Actualizar
   README, TESTING, manifest, registro, esta lista y guía de continuación.
   Conservar originales y configuración privada de forma duradera; no depender
   solo del scratch local ni guardar valores descifrados en el repositorio.
9. **Habilitar y desplegar con evidencia.** Solo conectar la ficha a `remote`
   después de completar el método y su acceso. La activación en producción
   requiere provisionar secretos reales y probar la ruta de descarga del
   backend desplegado. Respetar el procedimiento VPS/HPKE, sus respaldos y
   verificaciones, y la autorización de despliegue del propietario. Ajustar la
   versión efectiva de catálogo cuando se publique el cambio según su política;
   esta revisión documental mantiene la fuente 59 y las 57 fichas.

## Criterio de cierre y forma de reportar

| Estado que puede afirmarse | Evidencia mínima |
| --- | --- |
| Lector offline validado | Muestra incluida/exportada y documento completo contrastado; no implica descarga remota. |
| Método remoto validado | CLI descarga realmente desde la fuente vigente con todos sus datos y descifra el catálogo completo. |
| Integrado en el código Cloud | Broker, secretos/provisión documentada, worker, gateway, ficha y control conectados y verificados; indicar qué transportes son simulados. |
| Operativo en producción | Código desplegado, secretos provisionados y descarga completa realizada por la ruta real del backend/app. |

**No cerrar una integración remota solo porque pasa el lector offline o un
mock.** Una descarga Python real tampoco demuestra por sí sola el egress de
Node, el despliegue o una conexión VPN. Reportar esas etapas por separado.
Si la app original descarga y el script no, continuar investigando la diferencia
hasta resolverla; si un requisito externo impide cerrar, dejarlo identificado
con precisión y sin afirmar que está terminado.

Al cerrar una fila, registrar commit, build, fecha, métricas/hashes, gestión de
secretos y pruebas de broker/worker/gateway. Moverla a un historial de casos
resueltos y recalcular pendientes desde el código; no borrar el antecedente ni
retirar la fila únicamente por haber añadido un proveedor o un botón.

## Desactivaciones que no equivalen a estas 9 integraciones pendientes

- Un switch del panel, mantenimiento o `CLOUD_SERVER_VPN_ENABLED=false` puede
  desactivar proveedores ya integrados. Se comprueba en el VPS, no se deduce
  de la ficha del código. Esta revisión no leyó el estado de producción.
- **VIP Snipher Pro** ya tiene descarga autenticada real validada: catálogo
  8.0.61, 47 servidores/273 redes. **ALFAISAL Tunnel+** ya tiene POST firmado
  real validado:4.0.20, 4 servidores/51 Networks/103 SSLNetworks. Si faltan sus
  secretos en el VPS, hay que provisionarlos; no regresarlos a pendientes de
  método sin evidencia. **IZPH VPN PRO** validó GET real 3234, 84/303 sin secreto.
  Estos ejemplos siguen teniendo su despliegue separado del método validado.
- **90NET** sigue pospuesto por instrucción expresa; no forma parte de estas
  fichas `remote:null`. SVPN Connect tampoco figura entre estas55 fichas;
  conservar su seguimiento como integración separada, sin anunciar código
  inexistente ni contarlo como catálogo desactivado.

Referencias de las integraciones usadas como modelo:
[VIP](../../decoders/Python/apps/VIP_Snipher_Pro/TESTING.md),
[IZPH](../../decoders/Python/apps/IZPH_VPN_PRO/TESTING.md),
[ALFAISAL](../../decoders/Python/apps/ALFAISAL_Tunnel_Plus/TESTING.md) y
[guía obligatoria de paridad](SERVER_VPN_NEXT_CHAT_GUIDE.md).
