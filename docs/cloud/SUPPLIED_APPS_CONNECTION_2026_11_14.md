# Conexión de las aplicaciones aportadas — ci/unity-ads-online-qa

Se añadieron 42 fichas públicas de catálogo (118 totales), 270 rutas de archivo y 65 prefijos de texto. Las 57 aplicaciones tienen inventario y revisión explícita. Las apps que solo importan perfiles o suscripciones no reciben un catálogo público ficticio. Los algoritmos aportados se conservan; DTunnel incorpora posteriormente el identificador autorizado por el propietario.

La versión base de catálogo es 83 para reflejar la activación autorizada de DTunnel; la reconciliación existente incrementa la versión efectiva aunque el VPS tenga un override superior. Se conservan favoritos, switches individuales, claves HPKE, firma y versión Android. No hace falta recompilar la APK para las nuevas fichas/rutas publicadas mediante el contrato existente. El flujo adicional de URL custom code de XtraVPN no se presenta como implementado en el cliente.

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

JetRoi, Marvs SSH y REG Tunnel rechazan sus muestras de catálogo. IGNIX aún declara CIPHER_PENDING; YLA tiene firma pendiente; XJ y Vertex requieren autenticación/integridad genuina del proveedor. DocNet conserva payloads cifrados y se entrega explícitamente parcial. MM usa descifrado de campos acelerado y conserva como parciales los campos cuyo tag no verifica, sin perder las ubicaciones ni el resto del documento. Ninguno de esos límites se corrige activando un Boolean.

La matriz completa y las pruebas están en analysis/platform/supplied-integrations/2026-11-14/. No se certifican las 57 aplicaciones ni se ejecuta despliegue de producción.
