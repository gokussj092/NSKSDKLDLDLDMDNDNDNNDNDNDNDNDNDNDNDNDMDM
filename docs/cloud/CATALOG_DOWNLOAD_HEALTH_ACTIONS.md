# Validación de descargas de catálogo en GitHub Actions

## Alcance

El workflow **Catalog downloads - warnings only** comprueba el catálogo real del
repositorio: actualmente 67 proveedores y 79 entradas, incluidas todas las fuentes
pareadas, las cuatro fuentes de MKK y NUR. Las ocho aplicaciones sin ruta remota
se incluyen con advertencia explícita; no se inventa una URL para ellas.

Se reutilizan los descargadores del servidor, sin modificar su código, permisos,
cabeceras, POST, firmas, validación DNS/TLS ni política de redirecciones. HTTP
Conexión conserva su resolución Firebase y limpieza de instalación temporal.
No se ejecuta el motor Python de descifrado ni se compila Android.

## Cuándo se ejecuta

- Push a feat/nuevas-integraciones o main cuando cambian el broker, su inventario,
  los protocolos, el comprobador o sus referencias.
- Pull request con esos cambios.
- Actions → Catalog downloads - warnings only → Run workflow: todos, o un ID
  concreto (por ejemplo, wolf-custom-vpn o tunneltweak).
- Programación diaria a las 09:17 UTC **solo cuando el workflow esté en la rama
  predeterminada**. GitHub no ejecuta el cron desde una rama de trabajo aislada.

Cada ejecución muestra una tabla en Summary y conserva un artefacto durante
14 días: report.json, summary.md y baseline-candidates.json.

## Resultados

| Resultado | Interpretación |
| --- | --- |
| Descargado | Respuesta completa, no vacía, sin indicios básicos de página/error |
| Contenido actualizado | Cambió SHA-256, pero el contenedor y la estructura raíz siguen iguales; no es fallo |
| Formato cambiado | Advertencia por cambio de tipo/estructura respecto a la referencia |
| Fuente no disponible | Advertencia de HTTP/red/timeout; no demuestra que cambió la criptografía |
| Configuración ausente | Credenciales o URL autorizada ausentes en Actions; no se comprobó esa descarga |
| Sin ruta remota | Proveedor inventariado cuyo broker remoto aún no está habilitado |
| Error interno | Falló el comprobador; el job sí termina con error para no ocultar defectos de CI |

Los problemas de los proveedores generan anotaciones warning y el job continúa
con el resto. No se usa continue-on-error para ocultar errores de programación.

**Solo descargar no demuestra que el descifrador siga funcionando.** Si cambia
una clave o algoritmo conservando el mismo contenedor cifrado, esta comprobación
no puede detectarlo. Se etiqueta decoderCompatibility=NOT_TESTED; una advertencia
señala revisión pendiente, nunca afirma falsamente que un método murió.

## Referencia de formato

scripts/ci/catalog-download-baseline.json conserva solo tipo de contenedor,
SHA-256 del cuerpo y SHA-256 de la estructura raíz, sin valores ni claves JSON
en claro. Los cambios de versión, nombres, contenido o número de servidores
no modifican la huella de estructura.

La primera descarga válida sin referencia se informa como tal. Los candidatos
se guardan en baseline-candidates.json para revisar y registrar una referencia
de transporte. No certifican ningún método de descifrado. Los cambios detectados
no sobrescriben la referencia automáticamente: siguen avisando hasta su revisión.

Para reproducir sin dependencias npm:

~~~bash
node --test scripts/ci/catalog-download-check.test.mjs
CLOUD_SERVER_VPN_ENABLED=true node scripts/ci/catalog-download-check.mjs --out /tmp/catalog-health
~~~

Para comprobar solo una aplicación, añadir --provider wolf-custom-vpn.
No aceptar destinos, cabeceras ni URLs desde argumentos de usuario.

## Credenciales de CI

Si el proveedor las necesita, configurar los secretos de Actions con los mismos
nombres que utiliza el servidor. Este cambio no copia ni recupera secretos del VPS.

- VIP: SPDECODE_VIP_SNIPHER_AUTHORIZATION.
- ALFAISAL: SPDECODE_ALFAISAL_API_KEY, SPDECODE_ALFAISAL_SIGNING_KEY,
  SPDECODE_ALFAISAL_DEVICE_UUID.
- Halcon: SPDECODE_HALCON_REQUEST_SECRET y SPDECODE_HALCON_CATALOG_PASSWORD
  (el guard existente requiere ambas; no se usa la segunda para descifrar).
- NUR: CLOUD_NUR_CATALOG_URL, validada por la allowlist del broker.

Los secretos ausentes y las restricciones de autenticación se reportan como
advertencias de configuración, sin intentar eludirlas. Los forks no reciben
los secretos del repositorio.

## Privacidad y límites

No se suben catálogos, cuerpos HTTP, tokens, cabeceras, contraseñas ni URLs.
Los cuerpos viven solo en memoria del worker y desaparecen al terminar.
En HTTP Conexión se desempaqueta únicamente el transporte para observar el
catálogo opaco: la contraseña del wrapper nunca se incluye en las huellas.

Cuatro comprobaciones simultáneas, hasta 45 segundos por fuente, hasta 16 MiB
en el observador y los límites propios de cada broker (normalmente 8 MiB).
Un worker se termina al agotar su plazo para que no queden sockets pendientes.
La ejecución no cambia la aplicación, el servidor, los switches de proveedores
ni el estado de mantenimiento.


## Primera ejecución validada

Se registraron 61 referencias de transporte después de la primera comprobación real:
67 proveedores, 79 entradas, 61 descargas válidas y 18 advertencias. Las 20 pruebas
pasaron y el job terminó en verde. [Resultados y límites](../../analysis/platform/catalog-download-health/2026-11-08/RESULTS.md).
