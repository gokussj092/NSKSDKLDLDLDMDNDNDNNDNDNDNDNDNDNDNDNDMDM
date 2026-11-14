# Conexión de las aplicaciones aportadas — ci/unity-ads-online-qa

Se añadieron 42 fichas públicas de catálogo (118 totales), 270 rutas de archivo y 65 prefijos de texto. Las 57 aplicaciones tienen inventario y revisión explícita. Las apps que solo importan perfiles o suscripciones no reciben un catálogo público ficticio. No se modifica ninguno de los scripts aportados.

La versión base de catálogo pasa de 81 a 82; la reconciliación existente incrementa la versión efectiva aunque el VPS tenga un override superior. Se conservan favoritos, switches individuales, claves HPKE, firma y versión Android. No hace falta recompilar la APK para las nuevas fichas/rutas publicadas mediante el contrato existente. El flujo adicional de URL custom code de XtraVPN no se presenta como implementado en el cliente.

## DTunnel Mod

El broker, el decodificador y el control del panel están conectados. La muestra de 49 perfiles pasó de extremo a extremo. El proveedor requiere el encabezado dtunnel-token (user_id autorizado). Sin ese valor no hay descarga funcional: la petición anónima observada devolvió HTTP 200 con cero bytes. No se muestra habilitado artificialmente.

Actualizar con el comando real del proyecto:

```bash
sudo spdecode update all ci/unity-ads-online-qa
```

Configurar desde un JSON privado que contenga el user_id autorizado, presente en el VPS (sustituir la ruta):

```bash
sudo spdecode catalog-auth dtunnel /ruta/privada/credentials.json
```

Ese comando se implementa en spdecodectl y usa catalog-auth.py: valida el JSON, actualiza cloud.env con modo 0600 y recrea únicamente web. Nunca muestra el identificador ni lo copia a Git. También se admite SPDECODE_DTUNNEL_REQUEST_ID en el entorno privado existente.

## Límites de producción

JetRoi, Marvs SSH y REG Tunnel rechazan sus muestras de catálogo. IGNIX aún declara CIPHER_PENDING; YLA tiene firma pendiente; XJ y Vertex requieren autenticación/integridad genuina del proveedor. DocNet conserva payloads cifrados y se entrega explícitamente parcial. MM usa descifrado de campos acelerado y conserva como parciales los campos cuyo tag no verifica, sin perder las ubicaciones ni el resto del documento. Ninguno de esos límites se corrige activando un Boolean.

La matriz completa y las pruebas están en analysis/platform/supplied-integrations/2026-11-14/. No se certifican las 57 aplicaciones ni se ejecuta despliegue de producción.
