# SP-DECODE Cloud — Guía de actualización de catálogos

Documento de referencia para próximos chats/PR. **Leer antes de integrar un proveedor o redactar novedades.** Las listas de Server VPN y What's New son **sistemas distintos**, con versiones y cachés independientes. Este documento recoge el estado del código a octubre de 2026; volver a comprobarlo si cambia la implementación.

## Actualización del catálogo compartido V1/V2 — 31 de octubre de 2026 (revisión 58)

- La revisión de código `CATALOG_VERSION=58` obliga a reconciliar la huella del catálogo público después de los cambios HTTP Jireh/JyFast. `c12-provider-controls.mjs` aumenta **monotónicamente** `switches.json.version` cuando cambia la huella; la versión efectiva de producción puede ser bastante mayor que 58. Nunca borrar, editar a mano ni reiniciar `switches.json` para forzar la descarga.
- **Compatibilidad actual:** el cliente V1 utiliza directamente `POST /api/v1/server-vpn/catalog` y `/watch`. El transporte protegido de la aplicación V2 despacha sus operaciones internas 10 (catálogo) y 13 (watch) a esas mismas rutas. Ambos reciben el mismo catálogo lógico y **la misma versión efectiva**, aunque el JSON interno diga `apiVersion:"v1"`. Ese campo se refiere al contrato de datos, no a la generación de la aplicación. **Los inventarios V1/V2 todavía no están separados en este código**; la separación será otro cambio de API y cliente, no una consecuencia de aumentar el número.
- `CLOUD_SERVER_VPN_CATALOG_VERSION` en `cloud.env` es un override mínimo y puede ser inferior a la versión persistente del panel. `spdecode update all` reconstruye web/worker, pero no cambia configuraciones persistentes ni hace que Android descargue sin consentimiento. Las versiones V1/V2 con soporte de caché remota deben efectuar su propia comprobación de versión.
- **Despliegue:** comprobar repositorio limpio y HPKE, usar `sudo spdecode backup` (el keyring HPKE externo requiere respaldo cifrado independiente), ejecutar `sudo spdecode update all fix/http-jireh-current-method` y `sudo spdecode status`. No usar `docker compose down -v`. No fusionar ni desplegar una rama distinta sin autorización.
- **Verificación pública desde el VPS:** con `POST /api/v1/server-vpn/catalog` y `{"knownVersion":0}` comprobar `unchanged:false`, versión efectiva y tarjetas `http-jireh`/`jyfast-vpn-ultra`. Con `POST /api/v1/server-vpn/watch` y `{"knownVersion":0}` comprobar la **misma** versión. Una petición posterior a `/catalog` con `knownVersion` igual al valor devuelto debe responder `unchanged:true`. El valor persistente puede ser superior a 58 y debe ser estrictamente mayor al visto anteriormente por los clientes afectados.
- **Validación móvil:** en V1 y V2, abrir la pantalla de formatos/Server VPN y usar la actualización manual, confirmar la descarga cuando corresponda o habilitar la opción de actualizaciones automáticas. Verificar una tarjeta nueva y el hash de icono. En V2 comprobar, además, sesión/Play Integrity y la negociación HPKE con un dispositivo físico. Una respuesta `/health/live=200` no prueba el éxito de la descarga protegida. `decodeEnabled:false` puede obedecer al estado de proveedor aunque el catálogo sea nuevo.

## Publicación Cloud C10 — revisión 38 (AWG / UA, 23-oct-2026)

- **Corrección de alcance (23-oct-2026):** Android 1.1.18 build 29 contiene soporte parcial para el catálogo C10, pero el propietario reprodujo que algunas extensiones nuevas seguían rechazándose. La **1.1.19 build 30** es la actualización única de cliente que sincroniza el catálogo cifrado antes de importar, habilita la actualización manual también desde Formatos y conserva campos de credenciales validados. **A partir de 1.1.19**, nuevas extensiones publicadas correctamente en Cloud no deben requerir APK nueva. El comportamiento de la APK real debe validarse con CI y pruebas del propietario.
- `.awg` = AboWaged VPN 1.0 (`cloudSupported:true`, sin contraseña externa); `.ua` = Ultra Custom (`cloudSupported:true`, `credentialFields:["password"]`). Ambos sufijos ya estaban en `cloud/web/content/file-formats.json`: **no duplicar** entradas ni publicar métodos criptográficos en la lista JSON.
- El motor `.ua` corrigió el tratamiento de referencias Unicode UTF-16 en XML; el motor `.awg` ya decodifica la exportación real aportada. Los motores siguen exclusivamente en `cloud/workers/python` / `decoders/Python` y se invocan por rutas fijas.
- Se incrementó el mínimo `CATALOG_VERSION` de 37 a 38 para forzar una nueva huella C12 y la actualización monotónica del caché cifrado de Android, incluso cuando el inventario público de 250 sufijos no cambia. No borrar ni editar manualmente el volumen `provider-control`.
- **Despliegue pendiente de ejecución en el VPS**. Después de aprobar CI, usar la CLI existente del VPS (sin APK):

```bash
sudo spdecode update all feat/austroplus-vpn-13-0-1-decoders
sudo spdecode status
curl -fsS https://api.spdecode.xyz/api/v1/health
curl -fsS https://api.spdecode.xyz/api/v1/ready
curl -fsS -X POST https://api.spdecode.xyz/api/v1/server-vpn/catalog \\
  -H 'Content-Type: application/json' -d '{"knownVersion":0}' \\
  | python3 -c 'import json,sys; d=json.load(sys.stdin); formats={x["suffix"]:x for x in d["formats"]}; assert d["formatCount"] >= 250; assert formats["awg"]["cloudSupported"] and formats["awg"]["credentialFields"] == []; assert formats["ua"]["cloudSupported"] and formats["ua"]["credentialFields"] == ["password"]; print("Catalog version:", d["catalogVersion"], "formats:", d["formatCount"], "AWG/UA OK")'
```

En Android, abrir **Formatos > Actualizar catálogo** (o el equivalente de actualización manual de Server VPN), aceptar la descarga, y probar los archivos originales. Si persiste «no soportado», comprobar que la APK instalada sea **1.1.19 build 30**, la versión anunciada por el VPS y la sincronización de la caché; no introducir rutas Kotlin para cada nueva extensión como solución ordinaria.

## A. Catálogo Server VPN (proveedores, iconos y disponibilidad)

**Archivos de referencia**
- `cloud/web/lib/server-vpn-catalog.mjs`: lista `ITEMS`, `CATALOG_VERSION`, iconos y estado `decodeEnabled`.
- `cloud/web/public/server-vpn-icons/<id>.png`: PNG reales, verificados por SHA-256 en servidor y Android.
- `cloud/web/lib/server-vpn-provider.mjs`: IDs y fuentes HTTPS autorizadas. Sin URL ingresada por el usuario.
- `cloud/web/lib/c12-provider-controls.mjs`: controles de proveedor y versión persistente.
- `cloud/web/app/api/v1/server-vpn/catalog/route.js`: catálogo HTTP.
- `cloud/web/lib/c10-catalog-watch.mjs` y `c10-catalog-push.mjs`: avisos de versión vía HTTPS.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/ServerVpnCatalogRepository.kt`: caché cifrada, versión e imágenes.
- `cloud/workers/python/engine.py`, `catalog_vpn_bridge.py`, `server.py` y `cloud/web/lib/server-vpn-gateway.mjs`: motor y contrato API/trabajador.

**Procedimiento al añadir una aplicación**
1. Confirmar nombre, identificador estable y correspondencia entre icono, app y script. Probar el método antes de habilitarlo; no inventar endpoints, tokens o credenciales.
2. Añadir y probar el motor en backend, si corresponde. Conservar el resultado completo y las secciones anidadas. Registrar la fuente aprobada únicamente en la allowlist HTTPS, no en el cliente.
3. Guardar el icono original en `server-vpn-icons/<id>.png` y comprobar que su hash coincide. Registrar la tarjeta en `ITEMS`.
4. Si aún no existe descarga remota autorizada, usar `remote:null`: la tarjeta puede mostrarse, pero `decodeEnabled:false`. Ejemplo: DTunnel Mod. No anunciarla como operativa si aún no lo está.
5. Si requiere activación administrativa, revisar también `c12-provider-controls.mjs` y las allowlists del backend. Ajustar pruebas de conteo, IDs e integridad.
6. **Incrementar `CATALOG_VERSION` cada vez que cambia el catálogo visible**, incluidos nombres, iconos, orden, proveedores o disponibilidad. La base histórica de este PR es 13/16 entradas; esos valores no deben copiarse como constantes eternas.

**Regla crítica del versionado:** `CATALOG_VERSION` es un mínimo de código, `CLOUD_SERVER_VPN_CATALOG_VERSION` es el valor del entorno y `/app/provider-control/switches.json` conserva una versión persistente que puede ser **mucho mayor** tras cambios del panel. El cliente solo actualiza al detectar un número nuevo superior. `synchronizeCatalogVersion()` compara la huella de IDs/nombres/iconos y la revisión mínima de código y aumenta de forma monotónica la versión persistente cuando cambia el catálogo, incluso al habilitar una tarjeta que ya existía. El listado `/catalog`, la vigilancia `/watch` y el aviso `publishCatalogUpdate()` deben utilizar esa **misma versión efectiva**. **Nunca reiniciar, borrar ni rebajar `switches.json`** para forzar una actualización; también guarda los proveedores desactivados.

**Comprobación después del despliegue autorizado:** consultar `POST /api/v1/server-vpn/catalog` con `{"knownVersion":0}`, revisar versión efectiva, lista de IDs e iconos. Repetir usando esa versión: debe devolver `unchanged:true`. Comparar `/watch` y la caché de una APK ya instalada. El cliente hace comprobaciones de versión y mantiene las imágenes cifradas; el watch no es push FCM. Un `spdecode providers status` puede mostrar el valor del entorno, no la versión efectiva del catálogo.

**Lección MKK Hyper:** al leer varios orígenes, conservar cada respuesta y sus errores por separado. Si una fuente falla, el JSON puede ser válido con `complete:false`, `isPartial:true` y `PARTIAL_SOURCE_FAILURE`. La API debe reconocer el contrato parcial específico de MKK; no debe convertirlo silenciosamente en `SERVICE_UNAVAILABLE`. Si todas las fuentes fallan, devolver un error explícito. Revisar límites de descarga, Base64, trabajador y respuesta final. `0 B` en el panel no identifica por sí mismo la causa. Nunca registrar datos descifrados.

Pruebas relacionadas: `cloud/web/tests/server-vpn-catalog.test.mjs`, `server-vpn-provider.test.mjs`, `server-vpn-version-sync.test.mjs`, `server-vpn-worker-contract.test.mjs`, `c10-catalog-push.test.mjs`, `c12-provider-controls.test.mjs` y `tests/test_cloud_server_vpn_transport.py`. Actualizar las aserciones antiguas de versiones y cantidad de apps cuando cambie el catálogo.

## B. Novedades Cloud / What's New (C11)

**Fuente editorial:** `cloud/web/content/whats-new.json`. **API:** `POST /api/v1/whats-new`. **Lógica:** `cloud/web/lib/whats-new.mjs`. **Android:** `CloudWhatsNewRepository.kt`. **Pruebas:** `cloud/web/tests/whats-new.test.mjs`.

**Reglas de publicación**
1. Acordar **qué cambios se publican ahora**. No repetir funciones antiguas. La v3 del 22/oct/2026 anunció 14 aplicaciones desde V2ray Tunnel Plus hasta UT Loop Pro VPN y la disponibilidad pendiente de EUT, ProNeet y UT Loop. La **v4 preparada en este PR (23/oct/2026)** incluye cinco bloques nuevos: catálogos Xhypher/7NET/AboWaged; archivos .1ftnl/.creeb/.awg y método .crev actualizado; mejoras NPVS v5/v1 y limitación v6; V2Box y textos NPV; sincronización segura de 250 sufijos y errores mejorados. El JSON v4 en Git no implica que la VPS ya esté sirviendo v4: comprobar el override `CLOUD_WHATS_NEW_JSON`, desplegar solo con autorización y validar la API. CREEB VPN y AM Tunnel Lite no deben anunciarse como descargas remotas activas.
2. Aumentar `version` a un entero **estrictamente superior al último que hayan visto los usuarios**. Nunca reutilizar una versión ya publicada para textos distintos. Actualizar `publishedAt`; mantener `schemaVersion:1` salvo migración de contrato.
3. Usar títulos y descripciones cortos. Se admiten emojis como ✅ y 🛠️, y categorías `feature`, `support`, `improvement`, `fix`. Cada ID debe ser único. No presentar funcionalidades pendientes como activas.
4. Localizar en los 14 idiomas de la app: `en`, `es`, `ar`, `fa`, `fr`, `id`, `ru`, `de`, `pt-BR`, `tr`, `vi`, `hi`, `ja`, `it`. El inglés es obligatorio para fallback. Límites: 1–12 ítems; título 100 caracteres, subtítulo 250, título de ítem 90, descripción 320 y documento total **16 KiB**. En descripciones se permiten saltos de línea para listas; siguen prohibidos HTML y controles inseguros. Las APK anteriores que todavía envían inglés para `tr`, `vi`, `hi`, `ja` e `it` requieren nueva APK para acceder a esas traducciones; actualizar solo VPS no cambia el código del cliente.
5. **Comprobar el override del VPS:** si `CLOUD_WHATS_NEW_JSON` tiene valor, sustituye por completo el JSON del repositorio. Antes del despliegue, retirarlo de forma controlada o actualizarlo al documento correcto; de lo contrario seguirá mostrándose el anuncio viejo. `spdecode config set` no admite esta variable: editar el fichero protegido de forma controlada, manteniendo permisos 0600 y backup. No volcar `/etc/spdecode/cloud.env` a logs ni al chat.
6. Actualizar las pruebas de versión, IDs y traducciones junto con el anuncio. Tras despliegue, consultar `POST /api/v1/whats-new` con `{"knownVersion":V,"locale":"es"}`, donde V es la versión previa: comprobar las nuevas entradas. Repetir con la versión nueva: debe responder `unchanged:true`.

**Entrega:** los avisos se consultan dentro de la APK al abrir/regresar con conexión y consentimiento y se muestran una vez por versión. **No son notificaciones push del sistema**. Cambiar estas novedades no obliga a recompilar Android si el cliente ya admite C11; el nuevo documento debe estar en el servicio web desplegado.

## C. Lista de control para un PR futuro

- Separar trabajo de **motor** / **catálogo Server VPN** / **novedades C11**; no cambiar una parte innecesariamente.
- Confirmar los datos originales del proveedor y el estado real de funcionamiento antes de añadirlo a la lista.
- Sincronizar la versión efectiva, respetar la persistencia y nunca retroceder la caché del cliente.
- Mantener pruebas y documentación coherentes; no permitir que una prueba antigua bloquee un cambio legítimo.
- Evitar anuncios históricos repetidos; una versión editorial nueva solo describe la entrega actual.
- Antes de afirmar que ya funciona públicamente, comprobar la VPS y los endpoints reales; un commit no significa un despliegue.
- Respetar la rama/PR y no fusionar ni publicar sin autorización. **Si el usuario pide solamente documentación, no modificar código ni esperar CI.**

### Referencias ampliadas

- `docs/cloud/C11_WHATS_NEW.md` — especificación completa de novedades.
- `docs/cloud/ADDITIONAL_VPN_PROVIDERS.md` — casos KSH, MKK y DTunnel Mod.
- `cloud/infra/vps/spdecodectl` y `cloud/infra/vps/provider-services.py` — procedimientos del VPS.

**Al empezar el próximo chat:** abrir este archivo y las fuentes enlazadas antes de proponer nuevos catálogos. Validar siempre el estado actual; los números históricos aquí son ejemplos, no versiones permanentes.

## C. APK y AAB 1.1.19 (30): condiciones de preproducción

El PR #96 contiene la versión de fuente **1.1.19 (versionCode 30)**. La
publicación estable y pública sigue **NO-GO** en `release/android-readiness.json`.
El workflow `Validate SP-DECODE` ejecuta pruebas unitarias y 268 pruebas
instrumentadas API 35. La tarea reutilizable
`.github/workflows/cloud-private-preproduction-apk.yml` depende de la
aprobación de **ambas** tareas y de que el PR sea interno, en la rama prevista.
Solo entonces puede utilizar los secretos permanentes para compilar
`assembleRelease` y `bundleRelease`; realiza comprobación de certificado,
identidad, HTTPS, contenido Cloud-only, alineación y hashes. Los resultados se
conservan 14 días como artefactos **privados**, no como GitHub Release ni como
publicación Play. Si fallan las pruebas o falta el certificado, **no hay paquete**.

La clave temporal generada en C8 es exclusivamente de CI; su AAB nunca debe
subirse a Google Play. El bundle de preproducción firmado con la clave
permanente sigue siendo un **candidato**, pues la aceptación de la clave de
subida requiere la comprobación en Play Console. Si el certificado de subida
se ha fijado en `SPDECODE_PLAY_UPLOAD_CERT_SHA256`, el workflow exige coincidencia.
No deben confundirse el certificado de firma de la aplicación de Google Play
con el de subida; pueden ser distintos. Después de QA en dispositivo físico,
solicitar autorización explícita para la publicación en prueba cerrada.
