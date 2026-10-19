# SP-DECODE Cloud — Revisión jurídica previa a Google Play

**Estado: PENDIENTE / BLOQUEANTE PARA PRODUCCIÓN.**
**Responsables:** titular del servicio SP-DECODE y asesoría jurídica con experiencia en privacidad, propiedad intelectual, software y comercialización digital.
**Alcance:** aplicación Android Cloud, API y worker alojados por el operador, página web, pruebas QA y publicación en Google Play.
**Última revisión del listado:** octubre de 2026.

> Este documento es una lista de trabajo, **no** un aviso de privacidad, contrato, dictamen jurídico ni certificación de cumplimiento. Los términos, las advertencias y la aceptación de usuarios NO sustituyen la legalidad del tratamiento ni previenen por sí solos una denuncia, demanda, reclamación por marca o sanción. Requiere revisión profesional antes de una publicación comercial.

## Bloqueantes pendientes

- [ ] **Titular responsable e identidad legal.** Determinar quién opera la aplicación y recibe datos (persona física o moral), nombre/denominación legal que corresponda, domicilio o mecanismo de contacto legal exigible, jurisdicción, identidad de desarrollador de Play Console y responsable de privacidad. El alias público del programador no sustituye necesariamente la identidad legal. No publicar datos personales privados en GitHub sin una decisión expresa y asesoramiento.
- [ ] **Aviso de privacidad y términos definitivos.** Redactar dos documentos distintos, coherentes entre sí, que expliquen el servicio, las limitaciones, la relación contractual, reclamaciones, modalidades de consentimiento, cambios de versión y contactos. Incorporar aviso simplificado oportuno cuando proceda. Versionar ambos y exigir nueva aceptación cuando corresponda.
- [ ] **Inventario preciso de datos.** Auditar con evidencias qué entra por Android y qué procesa la API: archivos VPN, configuraciones, servidores, credenciales, contraseñas/HWID, referencias o enlaces externos, IP, tokens temporales, datos de integridad y telemetría. Distinguir datos ingresados voluntariamente de los metadatos necesarios. Evitar afirmaciones absolutas de «no almacenamos ningún dato» antes de verificar logs, Redis, Nginx, backups, crash reporting y SDKs.
- [ ] **Finalidad, base legal, transferencias y encargados.** Determinar base jurídica por finalidad; explicar quién recibe información, qué se envía al VPS y si algún proveedor externo recibe referencias o solicitudes. Documentar alojamiento, subencargados, regiones, transferencias internacionales, protección contractual y cualquier condición de proveedores.
- [ ] **Conservación, eliminación y solicitudes de los usuarios.** Establecer periodos verificables para archivos temporales, logs, sesiones, métricas, respaldos y cachés; explicar el historial cifrado local. Definir canal y procedimiento para acceso/rectificación/cancelación/oposición (cuando apliquen), revocación, borrado y quejas. Distinguir retirada del consentimiento de eliminación de información ya conservada.
- [ ] **Autorización para procesar perfiles de terceros.** Evaluar con asesoría jurídica el uso de claves, formatos propietarios, ingeniería inversa, medidas tecnológicas, configuraciones protegidas por contraseña y condiciones contractuales de cada aplicación VPN; no asumir que el consentimiento del usuario autoriza el acceso a secretos de otro titular. Limitar la función a archivos del usuario o que tenga derecho a procesar; registrar decisiones de habilitación/deshabilitación por proveedor. Analizar las leyes aplicables a cada región donde se ofrecerá la app.
- [ ] **Marcas, iconos y presentación.** Verificar legitimidad del uso de nombres e iconos originales de NUR, HX, 24clan, MKK y otros proveedores. Evitar aparentar colaboración, patrocinio o carácter oficial. Documentar licencias/permisos, atribuciones o alternativas aprobadas por titular cuando sean necesarias.
- [ ] **Seguridad y respuesta a incidentes.** Auditar TLS, Android Keystore/AES-GCM, directorios privados sin backup, acceso de administradores, rotación de secretos, workers aislados, borrado efectivo y filtrado de logs. Definir registro interno de incidentes, contacto, evaluación de riesgos, respuesta, notificaciones y conservación de evidencias sin exponer contenidos sensibles.
- [ ] **Google Play — User Data y Data safety.** Mantener URL HTTPS pública, activa y accesible sin autenticación o bloqueo geográfico para la política. Publicarla dentro de la app y Play Console. Completar Data safety con las prácticas reales de recogida/compartición, incluidas bibliotecas/SDK, y comprobar coherencia entre diálogos, política, formulario y comportamiento. Revisar políticas de propiedad intelectual, contenido engañoso, permisos, seguridad y terceros. Si en el futuro hay cuentas de usuario, aplicar las reglas de eliminación correspondientes.
- [ ] **Territorios y público objetivo.** Revisar como mínimo la Ley Federal de Protección de Datos Personales en Posesión de los Particulares (México) y sus normas aplicables. Si se distribuye en otros países, revisar también las leyes territoriales que correspondan. Evaluar edad de usuarios y medidas adicionales si puede ser accesible a menores.
- [ ] **Pruebas documentadas de cumplimiento.** Generar una matriz «declaración legal → función real → evidencia de prueba → versión/fecha». Validar aceptación previa al envío, revocación, ausencia de requests posteriores a revocación, caducidad de sesiones y eliminación según plazos. Revisar los documentos cada vez que cambien API, proveedores, datos o monetización.

## Controles técnicos ya incorporados, no equivalentes a validación legal

- Caché de catálogo/iconos y aceptación cifradas en almacenamiento privado Android, con clave Android Keystore AES-256-GCM; versión de catálogo y revisión periódica.
- Mecanismo de aceptación y retirada del consentimiento Cloud en la app.
- Uso previsto de transporte HTTPS, sesiones temporales y worker de descifrado del lado servidor.
- Proveedores remotos restringidos por reglas técnicas y funciones activadas explícitamente.
- Documentación actual en `cloud/web/app/privacy/page.jsx` y `cloud/web/app/terms/page.jsx` **todavía provisional**.

**Advertencia:** la instrumentación de un dispositivo comprometido (p. ej. Frida/root) puede observar datos mientras se descifran en memoria. No prometer invulnerabilidad. La presencia de un diálogo legal, cifrado local o una verificación de integridad no avala por sí sola derechos sobre terceros, licencias o conformidad normativa.

## Criterios de cierre antes de habilitar publicación general

1. Dictamen/revisión de un profesional jurídico para los territorios iniciales y los formatos de terceros que realmente se habilitarán, con correcciones identificadas.
2. Datos reales del responsable, contacto y procedimientos legales completos; documentos finales accesibles por HTTPS y versionados.
3. Inventario y auditoría técnica de datos en cliente, web, worker y servidor; políticas de conservación ejecutables y comprobables.
4. Aprobación de propiedad intelectual/marcas y de cada integración de formato/proveedor que se anuncie como compatible.
5. Formulario Google Play Data safety verificado contra comportamiento real y documentación.
6. Pruebas QA y de emulador/dispositivo con evidencias, sin subir datos privados al repositorio; trazabilidad del consentimiento y revocación.
7. Revisión final de lanzamiento y decisión documentada de publicación del responsable. No marcar este listado como «completo» solo porque CI esté en verde.

## Referencias oficiales para consultar en la revisión

- Google Play — User Data: https://support.google.com/googleplay/android-developer/answer/10144311
- Google Play — Data safety: https://support.google.com/googleplay/android-developer/answer/10787469
- Google Play — Prominent disclosure and consent: https://support.google.com/googleplay/android-developer/answer/11150561
- México — Ley Federal de Protección de Datos Personales en Posesión de los Particulares (texto vigente): https://www.diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf
- Procedimiento interno de Cloud QA: `docs/cloud/C8_VPS_INSTALLER.md`

## Seguimiento

**Fase VII:** pruebas de descifradores, seguridad y paridad con QA (no constituyen asesoría ni aprobación legal).
**Fase VIII:** despliegue de la versión aprobada y controles de operación, condicionado a los bloqueantes de publicación si es lanzamiento público.
**Prioridad legal:** alta antes de una distribución general o monetización. Puede desarrollarse en paralelo con QA privado autorizado.
