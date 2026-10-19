# SP-DECODE Cloud — Guía para ampliar Server VPN en otro chat

**Estado:** ampliación de catálogo POSPUESTA. Esta guía no habilita proveedores nuevos.
**Alcance:** exclusivamente backend Cloud y módulos Python. No modificar Android ni el panel web.

## Organización por aplicación

Conservar una carpeta por aplicación bajo `decoders/Python/apps/<APP_NAME>/`, reutilizando nombres existentes.

- `file_decoder.py` para archivos exportados, únicamente si existe ese formato.
- `server_catalog_decoder.py` para el catálogo remoto, únicamente cuando se dispone de uno.
- `README.md` con app, versiones analizadas, extensiones, dependencias y limitaciones.
- `TESTING.md` con pruebas sin valores privados, casos satisfactorios y fallidos.
- `manifest.json` con ID estable, tipo de motor y versión compatible.

Los módulos pueden mantener los nombres actuales del repositorio. No duplicar motores históricos.

## Integración Cloud existente

1. Mantener una función `run(data: bytes) -> str` para un decodificador autónomo y reproducible.
2. Registrar cada extensión aplicable en el inventario y router Python, preservando formatos anteriores.
3. Registrar el decodificador de servidores en `cloud/workers/python/catalog_vpn_bridge.py`, por ID fijo.
4. Incorporar el proveedor validado en `cloud/web/lib/server-vpn-provider.mjs`.
5. Publicar únicamente metadatos en `cloud/web/lib/server-vpn-catalog.mjs`.
6. Colocar el icono PNG original autorizado en `cloud/web/public/server-vpn-icons/` y registrar su checksum.
7. Añadir pruebas de paridad de los resultados JSON completos, validación, límites y manejo de errores.
8. Actualizar la versión del catálogo de forma monotónica al introducir nuevos proveedores.

El nombre y el icono se muestran en un único catálogo Android existente. No incluir en el APK métodos de descifrado, datos del proveedor ni información interna del backend.

## Entrega obligatoria

- Identificar versión y formato de cada muestra autorizada y documentar qué se comprobó.
- Los archivos con contraseñas/HWID se prueban con autorización y datos de prueba; no incluir información real en PR o CI.
- El adaptador de descarga nunca aceptará una ubicación arbitraria proporcionada por la aplicación.
- La interfaz pública no expondrá información interna de la API ni detalles operativos del servidor.
- Todas las pruebas automatizadas deben terminar correctamente antes de habilitar un método.
- Abrir PR independiente, sin fusionar a main, desplegar ni publicar APK sin autorización.
- Adjuntar listado de archivos creados, rutas del backend actualizadas y compatibilidad confirmada.

## Instrucción reutilizable para un nuevo chat

> Trabaja en el repositorio Gh0stDeveloper/SP-DECODE, en la rama de trabajo indicada. Analiza el APK y ejemplos que te proporcionaré y para los que cuento con autorización. Dentro de decoders/Python/apps crea o reutiliza una única carpeta por aplicación. Extrae por separado el decodificador de archivos y el del catálogo de servidores, si existen. Integra las rutas Python y los metadatos del catálogo en el backend Cloud, con pruebas reales de paridad y el icono original autorizado. No modifiques el APK Android, la interfaz existente ni la web administrativa. No registres información sensible en archivos publicados. Deja el trabajo en un PR sin fusionar y documenta los pendientes.

## Pendientes hasta el próximo análisis

- Métodos de nuevos servidores y catálogos: pendientes de incorporación y pruebas.
- Habilitación pública de los proveedores: pendiente de verificación individual.
- Revisión jurídica de marcas, iconos y tratamiento de datos: `docs/cloud/LEGAL_PRELAUNCH_REVIEW_PENDING.md`.
- Mantener intactos los métodos y catálogos ya operativos durante la fase VII.
