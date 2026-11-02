# SP-DECODE 1.1.26 — build 41: plan de navegación y funciones

Fecha: 2 de noviembre de 2026. Estado: **especificación solicitada; implementación pendiente**.

## Alcance y versión

El propietario solicita preparar la siguiente versión de trabajo: **1.1.26, build 41**, sucesora de **1.1.25, build 40**. Este documento registra decisiones de producto y criterios para su implementación posterior. Su incorporación no modifica código, pantallas, cobros ni los valores actuales de Gradle.

El trabajo comprende trasladar Formatos a Ajustes, reservar su posición de navegación para análisis de APK, distinguir estados de métodos del catálogo, añadir errores y sugerencias, y dar a Acerca de su propia pantalla. Debe conservarse el diseño de la aplicación.

Las mejoras de compatibilidad, atestación y reducción de solicitudes ya preparadas siguen formando parte de la base de trabajo. Véase [Compatibilidad administrable y solicitudes Android](ADMIN_COMPATIBILIDAD_Y_SOLICITUDES_2026_11_02.md).

## 1. Formatos soportados dentro de Ajustes

La sección Formatos deja su posición actual de la navegación principal. En **Ajustes → Formatos soportados** habrá una entrada que abre una pantalla propia.

Esa pantalla conserva la información de formatos y protocolos admitidos, sus descripciones y distinciones actuales. Debe reutilizar el catálogo verificado guardado en el dispositivo. Abrirla o volver a ella no debe iniciar una descarga ni otra consulta al servidor.

La lista completa no se incrusta en Ajustes: solo se muestra su entrada de acceso, con título, icono y descripción breve. Al volver se regresa a Ajustes y se conserva su estado de navegación.

Revisar la preferencia de última pestaña, los accesos existentes y la navegación hacia atrás al cambiar el destino de la antigua sección.

## 2. Nuevo espacio para aplicaciones y análisis de APK

La posición que deja Formatos se destina al futuro módulo para importar una APK y obtener material útil para preparar un script. **Aplicaciones / Análisis de APK** es un nombre de trabajo; el texto final del botón queda pendiente.

La intención del módulo es reducir la búsqueda manual: el usuario aporta la APK y obtiene un informe organizado que puede entregar al desarrollador o al asistente para investigar e implementar el método correspondiente.

### Presentación prevista inicialmente

En 1.1.26 se prepara una pantalla con el estado visible **Próximamente**, acorde con las demás secciones. Debe explicar brevemente el propósito del análisis, su acceso por suscripción y el coste por APK.

Mientras el servicio no esté activo, esa pantalla no debe simular análisis, aceptar un envío que no pueda procesarse ni cobrar créditos. Los controles de importación o análisis se presentan como no disponibles. La pantalla informativa sí puede abrirse.

### Flujo futuro cuando se active el servicio

1. Importar voluntariamente un archivo APK mediante el selector de archivos.
2. Mostrar el archivo seleccionado y los datos identificables de la aplicación.
3. Mostrar el acceso por suscripción, el saldo y el coste antes de confirmar el análisis.
4. Procesar el archivo y presentar progreso, cancelación, errores o resultado.
5. Permitir guardar o compartir un informe que sirva de base para crear el script.

Importar una APK no significa instalarla, abrir una aplicación instalada ni ejecutar su código. La primera propuesta técnica es analizarla estáticamente. Si más adelante se necesita otro tipo de análisis, debe especificarse por separado.

### Material que debe preparar el análisis

El alcance exacto se definirá durante la implementación, priorizando:

- Nombre de la aplicación, paquete, versión, build, huella del archivo y metadatos de firma disponibles.
- Inventario de manifiesto, recursos, assets, archivos de configuración y bibliotecas relevantes.
- Referencias útiles para investigar formatos, catálogos o comunicación de la aplicación, con su ubicación de origen.
- Observaciones técnicas, datos no disponibles y límites del análisis, diferenciando hechos comprobados de candidatos por investigar.
- Informe legible y datos estructurados que permitan continuar el trabajo sin volver a buscar todo desde cero.

El resultado es **material de investigación para preparar el script**. Una APK importada no demuestra por sí sola que se haya recuperado un método, obtenido un catálogo válido o construido un script funcional. Los hallazgos deben conservar su procedencia y no presentarse como un descifrado ya verificado.

### Modelo comercial solicitado

| Concepto | Definición |
| --- | --- |
| Acceso al módulo activo | Bajo suscripción |
| Coste de una APK | 1 crédito |
| Precio de un crédito | 4 USD |
| Estado inicial de la pantalla | Próximamente |
| Cuota y periodicidad de suscripción | Por definir |
| Créditos incluidos en la suscripción | Por definir |

No se asume que la suscripción cueste 4 USD: ese importe corresponde a **un crédito**. Tampoco se asumen planes, paquetes, renovaciones ni promociones que el propietario no haya definido.

Antes de activar pagos deben resolverse el canal de compra, la relación entre suscripción y créditos, la caducidad del saldo y el tratamiento de cancelaciones, archivos inválidos, APK repetidas, resultados parciales y análisis fallidos.

El consumo debe validarse en el servidor y evitar cargos duplicados por reintentos de una misma operación. El momento exacto de reserva, descuento y eventual devolución del crédito queda pendiente de definición.

Esta especificación asigna ese precio al análisis de APK; no introduce cambios comerciales para las funciones actuales.

## 3. Estados de los métodos del catálogo Server VPN

Mantener la etiqueta **Nuevo** e incorporar **Actualizado** y **En mantenimiento** para que el usuario distinga qué ocurrió con cada método.

| Etiqueta | Significado | Comportamiento previsto |
| --- | --- | --- |
| Nuevo | Se incorporó un método o una aplicación al catálogo | Conservar la indicación actual de novedad |
| Actualizado | Cambió el método de una aplicación ya incluida | Indicar la actualización de esa entrada |
| En mantenimiento | El método está temporalmente sujeto a mantenimiento | Mostrar su situación y evitar una operación que el servidor haya deshabilitado |

**Actualizado** se refiere a un cambio del método: no debe aparecer en todas las tarjetas solo porque aumentó la versión general del catálogo o cambió un icono.

**En mantenimiento** debe ser un estado explícito comunicado por el servidor. No se deduce automáticamente de una descarga fallida, falta de credenciales, ausencia de conexión o cualquier método deshabilitado por otra razón.

Propuesta de presentación: si coinciden estados, dar prioridad visual a En mantenimiento, después a Actualizado y luego a Nuevo. El detalle puede conservar información adicional. La duración y el mecanismo para dar por vistas las etiquetas deben definirse sin hacerlas reaparecer en cada descarga.

Cada entrada necesita datos de revisión del método y estado de mantenimiento. Esos datos deben viajar en la **misma respuesta del catálogo**, junto con los datos ya existentes: no crear consultas por tarjeta, por etiqueta ni al cambiar de pestaña. El servidor sigue decidiendo la disponibilidad real de la operación.

Las etiquetas deben tener texto accesible, contraste suficiente y traducción; el significado no puede depender solo del color.

## 4. Errores y sugerencias en Ajustes

Añadir **Ajustes → Errores y sugerencias**, con su propia pantalla. Debe servir tanto para proponer aplicaciones o métodos como para reportar problemas o sugerir mejoras.

Tipos previstos:

- Sugerir aplicación o método.
- Reportar un error.
- Proponer una mejora u otro comentario.

### Solicitud de una aplicación o método

El formulario debe permitir pegar el enlace de la aplicación —por ejemplo, su ficha o fuente oficial— y describir **qué se quiere integrar**: archivos, catálogo de servidores, exportación u otra función concreta.

Para esta categoría se requieren un enlace válido y una descripción. No basta con enviar un enlace sin explicar lo solicitado.

Este formulario envía una propuesta de integración; no es el flujo de análisis de APK y no debe descontar un crédito por enviar una sugerencia.

### Reporte de errores

El formulario permite marcar **una o varias casillas** correspondientes a errores concretos: descifrado, descarga del catálogo VPN, importación, exportación/unlocked, cierre inesperado, acceso Cloud/servidor u otros. Seleccionar **al menos una casilla** es obligatorio. El informe escrito sobre los pasos, detalles o resultados observados es **opcional**; no se fuerza texto cuando hay una casilla marcada.

La versión y build de SP-DECODE pueden adjuntarse como contexto técnico visible. No adjuntar automáticamente contraseñas, claves privadas, archivos importados, contenidos descifrados ni registros completos.

### Envío y recepción

Validar campos, mostrar el estado de envío, conservar el texto si falla la conexión y confirmar la recepción únicamente cuando el servidor la haya aceptado. Evitar duplicados por pulsaciones repetidas y devolver una referencia de solicitud.

La recepción y gestión desde el panel administrativo es la propuesta inicial; el destino definitivo, las categorías de seguimiento y la opción de contacto con el usuario quedan pendientes. No se configura un envío automático a correo o Telegram en esta etapa documental.

Abrir el formulario no envía solicitudes. El envío ocurre cuando el usuario confirma.

## 5. Acerca de en una pantalla propia

En Ajustes se conserva una entrada breve **Acerca de SP-DECODE** que abre una pantalla dedicada. Se trasladan allí los bloques informativos extensos para que Ajustes quede más limpio.

La pantalla debe organizar la información del proyecto y desarrollador, versión y build instaladas, canales oficiales existentes, privacidad, términos y licencias. Los agradecimientos, enlaces de apoyo o donación que ya existan pueden agruparse allí según el diseño final.

La versión mostrada se obtiene de la aplicación instalada; no se fija permanentemente en un texto de 1.1.26. Los enlaces deben ser los oficiales confirmados del proyecto.

## 6. Navegación y diseño

| Acceso | Destino previsto |
| --- | --- |
| Antigua posición principal de Formatos | Aplicaciones / Análisis de APK, con Próximamente |
| Ajustes → Formatos soportados | Pantalla de formatos |
| Ajustes → Errores y sugerencias | Formulario por tipo de solicitud |
| Ajustes → Acerca de SP-DECODE | Pantalla informativa independiente |

Conservar el tema AMOLED y los demás temas admitidos, tipografía, iconografía, tarjetas, espaciados, transiciones y estilo de controles de la aplicación actual. La reorganización no implica cambiar su identidad visual.

Traducir los textos nuevos a los **14 idiomas actuales**, incluyendo estados, ayuda, validaciones y accesibilidad. Revisar RTL, tamaños de letra grandes y pantallas compactas. Ajustes debe ofrecer entradas claras, no mostrar de nuevo todo el contenido de cada pantalla.

Mantener la navegación hacia atrás y no perder el catálogo, el historial ni las preferencias al reorganizar las secciones.

## 7. Plan de implementación posterior

| Trabajo | Estado en este documento |
| --- | --- |
| Destino 1.1.26 y build 41 | Registrado; cambio de Gradle pendiente |
| Mover Formatos a Ajustes | Especificado; implementación pendiente |
| Pantalla de APK con Próximamente | Especificada; implementación pendiente |
| Análisis real de APK y suscripción/créditos | Función futura; decisiones de servicio y cobro pendientes |
| Etiquetas Actualizado y En mantenimiento | Especificadas; contrato de catálogo, panel y cliente pendientes |
| Errores y sugerencias | Especificado; pantalla y recepción pendientes |
| Acerca de independiente | Especificado; implementación pendiente |

Orden sugerido: reorganizar navegación y Acerca de; añadir la pantalla Próximamente; incorporar los estados del catálogo y su administración; implementar errores y sugerencias; cerrar después el diseño técnico y comercial del análisis de APK antes de activarlo.

## 8. Criterios de aceptación para la futura implementación

- Formatos se abre desde Ajustes y ya no ocupa su antigua posición principal.
- El espacio nuevo muestra Próximamente y el modelo de créditos indicado, sin análisis ni cobros ficticios.
- Nuevo, Actualizado y En mantenimiento describen estados distintos y corresponden a datos reales del método.
- No aumenta el número de consultas del catálogo por abrir pantallas o mostrar etiquetas.
- Es posible proponer una app mediante enlace y descripción, y reportar errores desde el mismo apartado.
- Los formularios tienen validación, estados de envío y confirmación de recepción verificable.
- Acerca de tiene pantalla propia y Ajustes queda más despejado, conservando el diseño.
- Los textos nuevos están completos en los 14 idiomas y la navegación funciona en RTL y con accesibilidad.
- El cambio efectivo a versionName 1.1.26 y versionCode 41 se realiza con la implementación y validación de esa versión, no por añadir este documento.
- Antes de activar análisis de pago se validan el procesamiento de APK, los límites de recursos, la privacidad y la retención de archivos, los pagos y el consumo de créditos sin duplicados.

## Continuidad entre chats

Para continuar, leer este plan y la documentación de compatibilidad enlazada al inicio. No confundir especificación con funciones ya entregadas: este cambio solo añade documentación. Mantener las mejoras existentes de seguridad y solicitudes al implementar la navegación nueva. Las demás ideas no descritas aquí quedan fuera de alcance hasta que el propietario las concrete.

## Registro de implementación — Fase 1 (navegación)

Rama: `fix/http-jireh-current-method`. Se traslada Formatos a **Ajustes → Formatos soportados** mediante pantalla propia y retorno a Ajustes. La lista conserva búsqueda y protocolos de texto desde la misma caché local o en memoria; abrirla no genera peticiones nuevas. La antigua pestaña ofrece **Análisis de APK / Próximamente** sin importación, ejecución, análisis ni cobros.

Se actualizan el tutorial, los 14 idiomas y pruebas de instrumentación de navegación. Compilación y pruebas Android remotas pendientes; el commit se prepara con `[skip ci]` por ahorro de GitHub Actions. La versión y build Gradle no cambian.

## Implementación Fase 3 — Estados de métodos Server VPN

**Rama:** `fix/http-jireh-current-method`. Se incorpora un contrato aditivo
`apps[].methodRevision` (entero 0..1 000 000) y `apps[].maintenance`
(booleano, explícito) en la respuesta **existente** del catálogo de Server VPN.
Las versiones Android anteriores ignoran los campos opcionales. No hay endpoints
por tarjeta ni búsquedas adicionales para etiquetas.

- **Nuevo:** mecanismo local original, 2 horas después de añadir una app; sin
  activar todos los proveedores durante la primera instalación.
- **Actualizado:** cuando el operador registra una **nueva revisión del método**
  desde el panel; el cliente compara revisiones verificadas almacenadas
  localmente y muestra la etiqueta durante 2 horas. Cambios de versión global,
  iconos o switches no incrementan `methodRevision`.
- **En mantenimiento:** el operador marca explícitamente la aplicación. La
  API incluye `maintenance:true`, bloquea operaciones del proveedor y
  Android desactiva la acción. No se infiere de fallas de red, credenciales,
  un método desconfigurado ni de un switch deshabilitado.
- Si coinciden estados, prioridad visual: **mantenimiento, actualizado, nuevo**.
  Las etiquetas tienen traducción en los 14 idiomas; no dependen solo del color.

**Persistencia del servidor:** el mismo volumen privado de controles de
proveedores guarda `methodRevisions` y `maintenance` con escritura atómica,
bloqueo, validación por lista fija de identificadores y aumento monotónico
de `catalogVersion` cuando cambia algo real. Los cambios operativos aparecen
en `/admin/providers` y se realizan mediante
`POST /api/admin/provider-methods` con la misma autenticación y CSRF del panel.
El botón «Marcar actualizado» es explícito y no se activa al actualizar iconos.
Sin nuevas credenciales ni filtraciones de claves.

**Publicación y compatibilidad:** versión base del catálogo elevada a 62 para
invalidar cachés al desplegar. El VPS sigue usando su versión monotónica
persistida; no sustituirla por 62 ni reducirla. El operador debe actualizar
y comprobar el servidor antes de esperar cambios en las APK conectadas.

**QA:** se añaden pruebas Node de revisión, mantenimiento, persistencia,
invalidación, aislamiento de ID y no reactivación; pruebas Android de prioridad
y expiración local. Compilación y ejecuciones automatizadas pendientes:
evitar GitHub Actions hasta validación agrupada de fases.

## Implementación — Fase 4: Errores y sugerencias

**Android (14 idiomas):** Ajustes → Errores y sugerencias abre una pantalla propia,
con tres categorías: solicitud de método APK, reporte de error y mejora. En
**nuevo método APK** se abre un campo de URL pública (Google Play, Uptodown u
otro proveedor HTTP/HTTPS) y una descripción de lo que se desea integrar.
En **reporte de error** se presentan siete casillas multi-selección; marcar
una o varias es obligatorio y el informe de texto es opcional. En mejoras
se solicita una descripción. No hay carga de archivos ni cobros por sugerir.
El formulario retiene campos y selecciones si falla la transmisión y
solo muestra un identificador cuando el servidor responde con aceptación.

**Transporte:** operación nueva `18` en el **mismo endpoint cifrado HPKE V2**,
con sesión, prueba firmada (PoP), vinculación Play Integrity y RASP. No se
introduce un endpoint Android público alternativo que salte estas barreras.
La recepción interna `POST /api/v1/feedback` requiere contexto de solicitud
verificado por V2; una llamada directa se rechaza.

**Datos:** el servidor valida categoría y campo obligatorio, prohíbe URL locales,
credenciales en URL, esquemas no HTTP y propiedades extra. No descarga ni
ejecuta la APK. Solo recibe la URL y lo que el usuario escribe o selecciona,
además de versión/build instalada. No adjunta automáticamente archivos,
resultados descifrados, capturas, credenciales ni registros de diagnóstico.
Límite de cinco solicitudes/hora por clave de sesión de dispositivo,
idempotencia por ID de envío, y referencia UUID emitida por servidor.

**Persistencia y futura fase 5:** Redis registra solicitudes pendientes en
`spfeedback:pending` por identificador, cada contenido en
`spfeedback:record:<uuid>` con TTL de **90 días**, máximo 500 IDs en cola.
La vista de administración, revisión y resolución de solicitudes pertenece
a la fase 5; esta fase establece la recepción, sin UI administrativa nueva.

**Verificaciones:** pruebas Node de esquema, fuentes variadas, casillas,
informe opcional, idempotencia y acceso autenticado; pruebas instrumentadas
Android de habilitación de envío por categoría. Compilación Android e
instrumentación no ejecutadas para no saturar GitHub Actions. Las ramas
`main` y `feat/version-offline-apk` no se modifican.


## Implementación — Fase 5: Bandeja administrativa de solicitudes

**Panel VPS:** nueva página independiente \`/admin/requests\`, visible en el menú
lateral como **Solicitudes**. Recibe el contenido que el Android V2 envía
voluntariamente durante la fase 4: nuevas propuestas de método APK, reportes
de errores con selección de casillas e informes opcionales, y sugerencias.

**Bandeja:** 20 solicitudes por página, máximo 500 identificadores vigentes,
con filtros de categoría, estado y prioridad. Estadísticas agregadas por
estado y categoría dentro del mismo GET; no se crean consultas por tarjeta.
Cada entrada indica referencia UUID, fecha, versión/build de la app, el
enlace público aportado (si es método), errores marcados, texto del usuario
y fecha de última revisión. Los enlaces **no se abren ni descargan de forma
automática** y, cuando se abren manualmente, se aíslan con
\`noopener noreferrer\` y \`no-referrer\`.

**Gestión interna:** estados \`new\`, \`reviewing\`, \`in_progress\`,
\`resolved\`, \`rejected\`, \`archived\`; prioridades \`low\`, \`normal\`,
\`high\`; nota interna de hasta 600 caracteres. El operador pulsa
**Guardar seguimiento** para registrar los cambios. La API usa
\`expectedRevision\` con comprobación y escritura atómica en Redis;
un segundo operador no puede pisar silenciosamente una revisión nueva.
Archivado es un estado recuperable y no borra el contenido de inmediato.

**Seguridad:** \`GET/POST /api/admin/feedback\`, autenticación de sesión
administrativa igual a las demás secciones y CSRF obligatorio en POST.
Respuesta \`private, no-store\`, validación de tipos, filtros y tamaños;
no se devuelven registros a clientes Android ni existe endpoint público
de búsqueda. Se usa el almacenamiento ya creado en fase 4:
\`spfeedback:pending\` (IDs) y \`spfeedback:record:<uuid>\` (datos).
Las escrituras usan \`SET KEEPTTL\` para **no ampliar** el vencimiento
individual de 90 días. No hay notificación al usuario ni importación APK
en esta fase.

**QA añadida:** pruebas Node de lista limitada, datos caducados, filtros,
estadísticas, autorización, CSRF, actualización con revisión esperada y
preservación de TTL; prueba de estructura de la página, navegación y
renderizado seguro. Compilación Next.js y ejecución de pruebas integrales
**pendientes** hasta validación consolidada; este commit utiliza
\`[skip ci]\` para no saturar GitHub Actions. No se cambian la versión
Android, \`main\`, ni la rama offline.


## Implementación — Fase 6: «Acerca de SP-DECODE» (primer diseño aprobado)

**Diseño:** pantalla independiente de Ajustes, AMOLED negro y gris, tarjetas
compactas y la misma jerarquía visual que el primer prototipo aprobado por el
usuario. Se descarta el diseño alternativo morado. No se altera la navegación
principal de cinco pestañas, la pantalla de formatos ni el formulario de
solicitudes. En Ajustes aparece una única opción «Acerca de SP-DECODE», sin las
antiguas tarjetas expandidas de versión y desarrollador. El botón físico Atrás,
así como la flecha de la pantalla, regresan a Ajustes.

**Identidad:** icono oficial vectorial ya disponible en
`R.drawable.ic_launcher_foreground`, nombre del producto, descripción breve,
versión y build desde `BuildConfig.VERSION_NAME` y
`BuildConfig.VERSION_CODE`, nunca fijados a 1.1.26/41. La versión actual
de Gradle se mantiene intacta. El total de idiomas se calcula de
`SupportedLanguages.options` excluyendo `system`, que no es un idioma.

**Tarjetas:** información de la aplicación (desarrollador, idiomas, versión),
funciones principales (archivos VPN, catálogo Server VPN, JSON/unlocked,
historial), seguridad y privacidad (Cloud V2 HPKE e integridad solamente en
builds Cloud; historial local cifrado en modo sin Cloud), enlaces legales
existentes y comunidad. Los documentos legales reutilizan el callback
`onLegalLink` (privacidad/términos) y no se duplican en Ajustes.
Se conserva «Retirar consentimiento Cloud» dentro de los ajustes de privacidad
porque es un control operativo y no una página informativa.

**Enlaces oficiales:** destinos fijos centralizados en `AboutOfficialLinks`:
`https://spdecode.xyz`, `https://t.me/GhostDeve`,
`https://t.me/+Ntu6EJMirrAwMzgx` (invitación correcta a la comunidad) y
`https://t.me/Gh0stDeveloper`. Se elimina la referencia anterior a
`https://t.me/CodeBreakersHub`. `MainActivity.openExternal` mantiene
una allowlist estricta de esos cuatro URL; no permite enlaces arbitrarios.
Abrir «Acerca de» no origina conexiones de red.

**Traducciones y pruebas:** 21 cadenas nuevas en cada una de las 14 carpetas
de idiomas de Android, sin duplicar las traducciones existentes. Se añade una
prueba instrumentada de la pantalla, lectura de versión/idiomas, retroceso,
enlace oficial y accesos a política/términos; se adapta la prueba previa
de Ajustes a la nueva navegación. La copia generada de Ajustes para builds
Cloud/QA conserva el punto de inyección de sus tarjetas; se retira solamente
una sustitución obsoleta del enlace anterior de Telegram.

**Límites de esta fase:** sin cambios al VPS, catálogo, exportaciones o
descifradores; no se incrementa la versión Android, no se fusiona a `main`,
no se toca la rama offline. Commit con `[skip ci]`: la compilación real de APK
y la ejecución de pruebas Android requieren un runner/SDK y quedan señaladas
como pendientes hasta verificación específica.
