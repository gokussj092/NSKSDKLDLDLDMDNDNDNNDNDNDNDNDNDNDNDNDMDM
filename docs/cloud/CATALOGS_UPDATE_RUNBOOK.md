# SP-DECODE Cloud — Guía de actualización de catálogos

Documento de referencia para próximos chats/PR. **Leer antes de integrar un proveedor o redactar novedades.** Las listas de Server VPN y What's New son **sistemas distintos**, con versiones y cachés independientes. Este documento recoge el estado del código a octubre de 2026; volver a comprobarlo si cambia la implementación.

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

**Regla crítica del versionado:** `CATALOG_VERSION` es un mínimo de código, `CLOUD_SERVER_VPN_CATALOG_VERSION` es el valor del entorno y `/app/provider-control/switches.json` conserva una versión persistente que puede ser **mucho mayor** tras cambios del panel. El cliente solo actualiza al detectar un número nuevo superior. `synchronizeCatalogVersion()` compara la huella de IDs/nombres/iconos y aumenta de forma monotónica la versión persistente cuando cambia el catálogo. El listado `/catalog`, la vigilancia `/watch` y el aviso `publishCatalogUpdate()` deben utilizar esa **misma versión efectiva**. **Nunca reiniciar, borrar ni rebajar `switches.json`** para forzar una actualización; también guarda los proveedores desactivados.

**Comprobación después del despliegue autorizado:** consultar `POST /api/v1/server-vpn/catalog` con `{"knownVersion":0}`, revisar versión efectiva, lista de IDs e iconos. Repetir usando esa versión: debe devolver `unchanged:true`. Comparar `/watch` y la caché de una APK ya instalada. El cliente hace comprobaciones de versión y mantiene las imágenes cifradas; el watch no es push FCM. Un `spdecode providers status` puede mostrar el valor del entorno, no la versión efectiva del catálogo.

**Lección MKK Hyper:** al leer varios orígenes, conservar cada respuesta y sus errores por separado. Si una fuente falla, el JSON puede ser válido con `complete:false`, `isPartial:true` y `PARTIAL_SOURCE_FAILURE`. La API debe reconocer el contrato parcial específico de MKK; no debe convertirlo silenciosamente en `SERVICE_UNAVAILABLE`. Si todas las fuentes fallan, devolver un error explícito. Revisar límites de descarga, Base64, trabajador y respuesta final. `0 B` en el panel no identifica por sí mismo la causa. Nunca registrar datos descifrados.

Pruebas relacionadas: `cloud/web/tests/server-vpn-catalog.test.mjs`, `server-vpn-provider.test.mjs`, `server-vpn-version-sync.test.mjs`, `server-vpn-worker-contract.test.mjs`, `c10-catalog-push.test.mjs`, `c12-provider-controls.test.mjs` y `tests/test_cloud_server_vpn_transport.py`. Actualizar las aserciones antiguas de versiones y cantidad de apps cuando cambie el catálogo.

## B. Novedades Cloud / What's New (C11)

**Fuente editorial:** `cloud/web/content/whats-new.json`. **API:** `POST /api/v1/whats-new`. **Lógica:** `cloud/web/lib/whats-new.mjs`. **Android:** `CloudWhatsNewRepository.kt`. **Pruebas:** `cloud/web/tests/whats-new.test.mjs`.

**Reglas de publicación**
1. Acordar **qué cambios se publican ahora**. No volver a anunciar características antiguas. La publicación de referencia del 20/oct/2026 es **versión 2** y contiene exclusivamente **KSH VPN**, **DTunnel Mod** (acceso remoto aún pendiente) y **correcciones de MKK Hyper**. Las novedades antiguas de HTTP Custom, HA Tunnel, Google Play, etc., no forman parte de esa publicación.
2. Aumentar `version` a un entero **estrictamente superior al último que hayan visto los usuarios**. Nunca reutilizar una versión ya publicada para textos distintos. Actualizar `publishedAt`; mantener `schemaVersion:1` salvo migración de contrato.
3. Usar títulos y descripciones cortos. Se admiten emojis como ✅ y 🛠️, y categorías `feature`, `support`, `improvement`, `fix`. Cada ID debe ser único. No presentar funcionalidades pendientes como activas.
4. Localizar en los nueve idiomas disponibles: `en`, `es`, `ar`, `fa`, `fr`, `id`, `ru`, `de`, `pt-BR`. El inglés es obligatorio para fallback. Límites actuales: 1–12 ítems; título 100 caracteres, subtítulo 250, título de ítem 90, descripción 320 y documento total **16 KiB**. No incluir HTML ni datos privados.
5. **Comprobar el override del VPS:** si `CLOUD_WHATS_NEW_JSON` tiene valor, sustituye por completo el JSON del repositorio. Antes del despliegue, retirarlo de forma controlada o actualizarlo al documento correcto; de lo contrario seguirá mostrándose el anuncio viejo. No volcar `/etc/spdecode/cloud.env` a logs ni al chat.
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
