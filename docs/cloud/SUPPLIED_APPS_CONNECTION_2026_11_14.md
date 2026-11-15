# Conexión de las aplicaciones aportadas — ci/unity-ads-online-qa

Se añadieron 46 fichas públicas de catálogo (122 totales), incluidas cuatro fichas pendientes desactivadas, 270 rutas de archivo y 65 prefijos de texto. Las 57 aplicaciones tienen inventario y revisión explícita. Las apps que solo importan perfiles o suscripciones no reciben un catálogo público ficticio. Los algoritmos aportados se conservan; DTunnel incorpora posteriormente el identificador autorizado por el propietario.

La versión base de catálogo es 84 para reflejar los estados pendientes y sus controles; la reconciliación existente incrementa la versión efectiva aunque el VPS tenga un override superior. Se conservan favoritos, switches individuales, claves HPKE, firma y versión Android. No hace falta recompilar la APK para las nuevas fichas/rutas publicadas mediante el contrato existente. El flujo adicional de URL custom code de XtraVPN no se presenta como implementado en el cliente.

## DTunnel Mod

El broker, el decodificador y el control del panel están conectados. El propietario suministró y autorizó incrustar el identificador de acceso el 2026-11-14. El script y el broker lo utilizan por defecto y la ficha se habilita sin configuración adicional. Prueba real con el valor autorizado: HTTP 200, 80.600 bytes y 49 perfiles, conservados completos por el worker.

Actualizar con el comando real del proyecto:

```bash
sudo spdecode update all ci/unity-ads-online-qa
```

Solo para sustituir posteriormente el valor integrado, se puede configurar desde un JSON privado en el VPS:

```bash
sudo spdecode catalog-auth dtunnel /ruta/privada/credentials.json
```

Ese comando opcional valida el JSON, actualiza cloud.env con modo 0600 y recrea únicamente web. También se admite SPDECODE_DTUNNEL_REQUEST_ID como override. Un override vacío usa el valor integrado; uno inválido falla cerrado. Las credenciales integradas quedan visibles en el repositorio público por autorización expresa, y se excluyen de metadatos y archivos web públicos. No hace falta ejecutar catalog-auth para usar el valor por defecto.

## Límites de producción

El propietario confirmó que JetRoi, Marvs SSH y REG Tunnel abren los catálogos incluidos en sus APK; el catálogo remoto cambió de clave después de 1.9.28.1. Esta confirmación no es una nueva prueba remota realizada por esta integración. RNV también mantiene pendiente la clave del servidor. IGNIX aún declara CIPHER_PENDING; YLA tiene firma pendiente; XJ y Vertex requieren autenticación/integridad genuina del proveedor. DocNet conserva campos cifrados y su resultado es parcial. Son límites conocidos de los métodos aportados, no defectos nuevos de sus scripts.

Los nueve catálogos anteriores quedan desactivados por defecto. Todos tienen controles en el panel, incluidos IGNIX, YLA, XJ y Vertex, que ahora aparecen como fichas pendientes con sus iconos originales. El interruptor administrativo se guarda independientemente de la disponibilidad técnica: se puede activar y desactivar aunque falte una clave o no exista aún un broker implementado. El panel muestra ambos estados. La descarga sigue bloqueada cuando falta el broker o su configuración; habilitarla no inventa claves, firmas ni identidades. JetRoi/Marvs/REG/RNV/DocNet conservan sus rutas existentes para su activación explícita por el operador. DTunnel continúa activo por defecto.

El estado persistente añade una lista `enabled` de activaciones explícitas junto a `disabled`; ambas listas son de IDs permitidos, no se solapan y se escriben atómicamente en el volumen de controles. Los archivos previos sin `enabled` siguen siendo válidos. Las desactivaciones anteriores se respetan; las activaciones de catálogos inicialmente desactivados sobreviven al reinicio y a la reconciliación de despliegue. Mantenimiento sigue siendo un control independiente. Los métodos de archivo y texto se conservan sin cambios.

MM usa descifrado de campos acelerado y conserva como parciales los campos cuyo tag no verifica, sin perder las ubicaciones ni el resto del documento.

La matriz completa y las pruebas están en analysis/platform/supplied-integrations/2026-11-14/. No se certifican las 57 aplicaciones ni se ejecuta despliegue de producción.
