# SP-DECODE — POLÍTICA OBLIGATORIA DE EVIDENCIAS Y SCRIPTS POR APLICACIÓN

**Vigencia documental:** 2026-11-02.  
**Estado:** regla de trabajo **OBLIGATORIA para nuevas investigaciones y revisiones**, con automatización CI pendiente de implementación.  
**Ámbito:** todo método de archivo, texto, catálogo VPN, descarga autorizada, exportación compatible, actualización de decodificador y nuevo proveedor que se integre en SP-DECODE.  
**Carpeta maestra:** analysis/ (nombre del repositorio en inglés). No confundir con scripts/apk_analysis/ ni con la documentación ANALYSIS.md existente dentro de cada decodificador.

## 0. REGLA INNEGOCIABLE

**PROHIBIDO declarar «método integrado», «actualizado», «verificado», «soportado» o «listo para producción» si no se guardó en Git el expediente de investigación del método, incluidos los SCRIPTS PROPIOS y herramientas reproducibles realmente usados para obtenerlo y probarlo, con sus versiones, comandos, límites y evidencias.**

- No se acepta como sustituto un texto narrativo, una respuesta del chat, enlaces a un entorno temporal, una captura aislada o un código final sin método de reproducción.
- No se permite borrar una herramienta al terminar, omitir un intento fallido significativo ni llamar «éxito» a resultados sintéticos o no autentificados.
- Se deben guardar las revisiones de las herramientas empleadas, no solo la versión final del decodificador, con trazabilidad de cómo fue descubierto el método.
- Si alguna herramienta era de terceros (JADX, apktool, dexdump, etc.) no copiar binarios ajenos ni código con licencia incompatible: guardar nombre, versión, origen, SHA-256 de distribución cuando se conozca, opciones invocadas y script propio de orquestación.
- La regla aplica también a correcciones, cambios de versión y reinvestigaciones, no solamente a nuevas aplicaciones.
- Si no se pudo verificar realmente el método, guardar el expediente igualmente con estado PENDING / FAILED / PARTIAL y mantener la integración no activa según la política del catálogo.

## 1. Organización canónica por paquete y build

~~~text
analysis/
  README.md
  METHOD_EVIDENCE_POLICY.md
  <package_id_normalizado>/                  # ej. com.creebtunnel.vpn
    README.md                                # matriz de builds y hallazgos
    <version_code_o_build>/                 # ej. 50
      MANIFEST.json                          # identidad, insumos, herramientas, alcance
      ANALYSIS.md                            # pasos y evidencia de investigación
      REPRODUCE.md                           # ejecución exacta desde raíz del repo
      RESULTS.md                             # estado probado, escenarios, límites
      tools/
        inspect.py                           # scripts propios para descubrir y analizar
        extract.py                           # solo si fue realmente usado
        verify.py                            # pruebas/oráculo reproducible
      tests/
        test_method.py                       # positivas y negativas sanitizadas
        fixtures/                            # sintéticas o autorizadas y sin secretos
      generated/                             # solo artefactos revisados y sanitizados
        ...                                  # nunca código sin revisión como «producción»
~~~

La carpeta <package_id_normalizado> deriva del applicationId real de Android, normalizado a [a-z0-9._-] con validación estricta. Un mismo paquete puede tener builds distintos. Mantener identificadores de método/vía dentro de MANIFEST.json (archivo, texto, catálogo) y no fusionar evidencia de versiones incompatibles.

## 2. Contenido obligatorio del expediente

### MANIFEST.json
Campos mínimos que el validador CI deberá exigir:
- schema_version; package_name; app_name; version_name; version_code; observed_at; source_category (usuario, tienda, archivo autorizado, asset incluido); rights/authorization_note (sin datos personales); status (VERIFIED, PARTIAL, PENDING, FAILED, MAINTENANCE);
- targets: lista de formatos/vías (files, text, catalog, export), con extensiones, versiones y estado independiente;
- inputs: tipo, tamaño, SHA-256, origen reproducible que respete privacidad; NO guardar APK privado ni credenciales;
- tooling: nombre, versión, licencia u origen, checksum opcional, ruta del script en analysis/.../tools y/o repositorio para herramienta compartida; entrada/salida prevista, argumentos y entorno;
- code_paths: vínculos a decoders/Python/apps/<Nombre>/codec.py, file_decoder.py, server_catalog_decoder.py, cloud workers y tests según correspondan;
- evidence_refs: archivos de prueba, reproducibilidad positiva/negativa, rutas de resultados sanitizados, fuentes y comparación independiente;
- limitations, network_requirements, manual_steps, unresolved_questions;
- no datos falsos para llenar campos. Datos no conocidos: null y explicación, no «validado» imaginario.

### ANALYSIS.md
- Objetivo, versión y paquete exacto, cómo se obtuvo la muestra autorizada, hashes.
- Métodos, capas de cifrado, empaquetado o estructuras interpretadas: **separar observación, hipótesis y verificación**.
- Herramientas usadas por orden, comandos, salida resumida, discrepancias y causas de fallo.
- En rutas remotas: evidencia de fuente, estado de autenticación/autorización, conteo real de registros, HTTP/tipo de dato y motivo de fallos, sin exponer tokens ni endpoint privado sensible.
- Alcance real: si un catálogo estático incluido funciona, NO afirmar que la descarga remota también funciona.
- Cambios frente a builds previos, compatibilidad heredada y pruebas regresivas.

### REPRODUCE.md y tools/
- Comandos que se ejecutan desde la raíz del repo con parámetros de entrada por ruta privada; Python/Node/Java/NDK/JADX y dependencias fijadas por versión.
- Guardar físicamente en tools/ TODOS los scripts propios escritos o modificados durante la investigación y necesarios para reproducir hallazgos, aun si el código operativo final está en otra carpeta. Evitar copias divergentes: origen canónico, checksum y sincronización declarada.
- Herramientas compartidas ya existentes en scripts/apk_analysis/: conservar su ruta, versión/commit/hash y la invocación exacta. Añadir wrapper o script de receta por app en analysis/.../tools cuando haya pasos propios. **No eliminar scripts/apk_analysis/**.
- Al actualizar cualquier script compartido, identificar qué expedientes y pruebas consumen esa interfaz.
- No depender de rutas efímeras de un contenedor, cachés personales, imágenes no reproducibles ni claves incrustadas.

### tests/ y RESULTS.md
- Al menos: test determinista positivo con referencia verificada cuando exista una muestra autorizada; test negativo (truncado, tag inválido, entrada corrupta, respuesta HTML o credencial ausente según formato); y verificación de esquema/JSON de salida.
- Registrar número de pruebas, comandos ejecutados, entorno, resultado, hash de fixtures, versión de decodificador. Indicar qué parte fue probada con oráculo independiente (JCA, Java original, golden vector legal, etc.).
- Un fixture sintético demuestra la lógica implementada, **no** prueba compatibilidad de una versión real ni conectividad remota. Diferenciar VERIFIED_REAL, VERIFIED_SYNTHETIC, REQUIRES_DEVICE, NOT_AUTHORIZED y NETWORK_UNAVAILABLE donde aplique.
- No inventar catálogos, servidores, respuestas HTTP, certificados ni JSON «descifrado».
- Si el método no está confirmado, conservar la hipótesis y los scripts bajo estado PENDING y un plan de siguiente prueba; no activarlo públicamente.

## 3. Prohibiciones y manejo de materiales

- PROHIBIDO subir a Git: archivos APK/APKS/XAPK privados sin derechos de redistribución, muestras de clientes, perfiles VPN reales con credenciales, JSON descifrado sensible, private keys, claves de firma, usuarios/contraseñas, tokens, Google Play Integrity tokens, cookies, secretos de proveedores o logs con datos personales.
- Los originales pueden analizarse localmente bajo autorización, con hash SHA-256 público, sin necesitar conservar bytes en Git. Guardarlos temporalmente en almacenamiento restringido y eliminarlos según política de privacidad.
- No recopilar credenciales ajenas, derrotar la autenticación de servicios o simular una atestación de Google como válida. Registrar cuando falta una autorización en lugar de falsificar éxito.
- Sanitizar entradas y salidas; usar URLs example.org, cuentas ficticias y golden vectors sintéticos si el original no es publicable.
- Los prompts para una futura IA tampoco podrán incluir secretos, perfiles privados o contenido propietario no autorizado. No almacenar materiales reales en embeddings sin consentimiento y control de acceso.

## 4. Flujo obligatorio de contribución (NEW + UPDATE)

1. Abrir análisis de versión concreta y preparar analysis/<paquete>/<build> ANTES de modificar el método operativo.
2. Guardar inventario original (hashes/versión), herramientas, scripts, comandos, resultados parciales, problemas y evidencias verificables.
3. Confirmar técnica de archivo/texto/catálogo de manera independiente; documentar compatibilidad y pruebas negativas.
4. Implementar o corregir en decoders/Python/apps/<Nombre>/ y worker/catálogo si procede; pruebas de integración aisladas.
5. Enlazar ese método desde el expediente y enlazar el expediente desde README o ANALYSIS.md del proveedor existente. Mantener rutas de scripts/apk_analysis si ya forman parte de otras pruebas.
6. Ejecutar tests; registrar resultado y estado real; **NO MARCAR DONE** si faltan scripts o evidencia reproducible.
7. Revisar ausencia de secretos/PII y licencia de herramientas; confirmar que no se escribió ningún binario de tercero en Git.
8. Solo después de aprobación técnica, proponer activar el método en catálogo/servicio. No fusionar a main, no desplegar VPS y no publicar app automáticamente.

Las peticiones de solo investigación (sin método funcional) también deben dejar expediente mínimo con scripts y estado PENDING. Si el equipo descubre un método manualmente, registrar un procedimiento reproducible o script de inventario antes de llamarlo integrado.

## 5. Bloqueo de CI requerido (PENDIENTE DE CÓDIGO, NO ACTIVO HOY)

**Requisito funcional de la siguiente implementación de tooling**: crear scripts/ci/check_method_evidence.py y un job requerido en GitHub Actions (branch protection, cuando el propietario lo configure). Debe:
- Leer git diff para detectar apps nuevas/cambios en decoders/Python/apps/, fuentes de catálogo, workers o scripts de método.
- Localizar analysis/<paquete>/<build>/MANIFEST.json actualizado, ANALYSIS.md, REPRODUCE.md, RESULTS.md, tools/, tests/.
- Validar JSON/schema, rutas locales, existencia de scripts, hashes esperados, estado coherente con «habilitado» y mínimo de pruebas; prohibir rutas temporales y secretos evidentes. No imprimir muestras al fallar.
- Ejecutar tests de inventario y regresión de expedientes alcanzados, compatible con CI offline (sin conexión a terceros ni datos privados).
- Bloquear merge cuando no exista el expediente requerido; mantener excepción explícita aprobada para cambios de documentación únicamente y modificaciones realmente no relacionadas.
- Para legado existente: establecer baseline de paquetes previos y no invalidar todo el repositorio; exigir expediente desde la PRIMERA modificación futura de cada método y abrir inventario de migración gradual. No introducir excepciones silenciosas por proveedor.

**Distinción de estado:** esta política ya es obligatoria para trabajos nuevos que realice cualquier asistente/colaborador, pero GitHub todavía NO la exige automáticamente mediante CI hasta que se implemente el check anterior y se active protección de rama. Ninguna documentación puede asegurar falsamente que existe ese bloqueo mecánico.

## 6. Reutilización por futuro servicio automático de APK

Este archivo es un contrato de procedencia para la futura función de APK (fase 7):
- El servidor podrá indexar SOLO los expedientes APPROVED/VERIFIED, scripts seguros, metadatos y fixtures sanitizados de analysis/.
- El índice registrará package, familias/versiones, signatures, técnicas, comandos reproducibles, resultados, límites y SHA-256 del commit/expediente. No importar claves ni bytes de APK originales.
- Reutilizar scripts probados como herramientas explícitas en un sandbox sin privilegios, sin dar a una IA capacidad para ejecutar comandos arbitrarios o acceder a red/secretos.
- Estado de la IA no convierte un método PENDING en VERIFIED; la validación depende de pruebas reales y revisión.
- Para el proyecto automático completo consultar docs/FASE_7_APK_AUTOANALISIS_DOS_SALIDAS_PENDING_2026_11_02.md.

## 7. Ejemplos concretos que deben servir como migración inicial

- CREEB VPN: decoders/Python/apps/CREEB_VPN/ANALYSIS.md y scripts/apk_analysis/creeb_vpn_remote_probe.py, creeb_vpn_verify.py; conservar límites de Play Integrity y la distinción remoto/estático.
- MTM Tunnel Lite: scripts/apk_analysis/mtm_verify.py, mtm_bundle.py y documentación de versión.
- UT Loop Pro: decoders/Python/apps/UT_Loop_Pro_VPN/ con pruebas y recetas; agregar expediente analysis/ al siguiente cambio.
- Hex Custom: scripts/apk_analysis/hex_custom_recover.py; preservar fuente de archivos y prueba real por variante.
- ANÁLISIS de SocksIP actual: analysis/SOCKSIP_VER8_VER7_VER6_STUDY.md es un documento histórico válido, pero NO sustituye el expediente por build requerido para integraciones nuevas.

**Referencias existentes:** scripts/apk_analysis/README.md; scripts/apk_analysis/RESTORE.md; docs/cloud/SERVER_VPN_NEXT_CHAT_GUIDE.md; docs/FASE_7_ARQUITECTURA_SUSCRIPCIONES_CREDITOS_APK_2026_11_02.md; decoders/Python/apps/README.md.
