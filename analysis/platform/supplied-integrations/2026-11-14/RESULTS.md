# Resultados de la integración

Estado: PARTIAL. Las conexiones implementadas pasan sus comprobaciones; no equivale a certificar todos los métodos aportados ni a un despliegue VPS.

- 69/69 pruebas Python de integración y regresión aprobadas (MM, 1FTunnel, V2Box, textos C2, catálogos previos, DTunnel y adaptadores nuevos).
- 87/87 pruebas Node específicas de catálogo, broker, nuevos proveedores, contratos y controles aprobadas.
- Suite web completa: 767 tests; 760 pasan, 4 fallan, 3 omitidos. Los cuatro fallos se reprodujeron en el commit base 24c4f69 con las mismas dependencias: admin-sidebar-navigation, legal-monetization (permisos), dos expectativas store-terms. No se modifican esas funciones ajenas a la conexión.
- npm run build: aprobado; Next 16.4.3 compila las rutas. Permanecen advertencias de trazado dinámico/workspace, sin error de compilación.
- Generador de formatos coincide con 270 rutas; metadatos de texto: 65; fichas públicas: 118.
- Importación de todos los módulos de catálogo y archivo aportados: aprobada.
- DTunnel: broker con transporte simulado más worker aislado real reproduce la muestra completa de 49 perfiles. Sin user_id, petición real anónima: HTTP 200, cero bytes; no se usa como prueba de autenticación ni de descarga funcional.
- MM: la muestra incluida se descifró completa con el worker en 69.09 segundos; antes agotaba 120 segundos. Se conservan los codecs completos de archivos MM/1FTunnel y las salidas históricas de prefijos RENZ.
- Muestras locales descifradas: AT NET, Binke, DTunnel, DocNet (parcial explícito), E-SAN, HAMARA, IP Tunnel, LinkLayer, Litron, MM, PUKANG, RNV, RoVPN, Shield Tunnel, Shield VPN, TRP, UDP Thunder, V2OVPN y VC.
- JetRoi, Marvs SSH y REG rechazan las muestras remotas por el cambio de clave conocido, según aclaración posterior del propietario; él verificó que los catálogos incluidos en APK sí abren. No se presenta esa verificación como una prueba remota nueva de esta integración.
- Ningún script original en decoders/Python/apps fue modificado. Se añaden únicamente adaptadores, inventario, fichas, copias públicas de iconos, controles y pruebas.

No ejecutado: actualización del VPS, nueva APK, publicación Play, extracción de credenciales ajenas, nuevos veredictos de integridad o pruebas autenticadas de proveedores que exigen datos no suministrados.

## Cierre de controles

Se ejecutaron además 151/151 pruebas Python de proveedores anteriores, aprobadas tras actualizar sus expectativas de inventario a 270 rutas. La auditoría F7-A0 con --enforce pasó con 82 expedientes estructuralmente completos, sin equivaler a validación remota. GitHub Actions compartido de caché pasó en 40a19fd. El primer preflight Android detectó una expectativa literal de COPY para V2Box ya desactualizada por la tanda anterior; se separa la instrucción COPY manteniendo todos los archivos y los 34/34 contratos de release pasan localmente. No se afirma una APK nueva compilada hasta que termine la ejecución remota.

## Revisión de controles y límites conocidos — 2026-11-14

Los nueve catálogos pendientes (JetRoi, Marvs SSH, REG, RNV, IGNIX, YLA, XJ, Vertex y DocNet) quedan desactivados por defecto, con estado administrativo persistente y reversible desde el panel. Todas las fichas, incluso las previas sin broker disponible, tienen control. Las cuatro nuevas fichas pendientes elevan el total a 122, sin añadir métodos ficticios. DTunnel mantiene su activación y no cambian los codecs de archivo/texto.

90/90 pruebas Node específicas aprobadas: controles, estado persistido, compatibilidad de estado antiguo, reactivación sin requisitos técnicos, mantenimiento independiente, reinicio de módulo, reconciliación, catálogo, broker, worker y autenticación del panel. El reproductor pequeño guarda 5/5 en generated/catalog-controls-proof.json. Estos resultados prueban los controles; las claves y capturas siguen pendientes. La versión base sube a 84.

La compilación web posterior al cambio pasó. La revisión completa suma 772 pruebas: 765 aprobadas, 4 fallos previos ajenos a estos controles y 3 omitidas; no aparecen regresiones nuevas. Las expectativas de ALFAISAL/VIP se adaptaron al nuevo contrato: se guarda la elección administrativa sin claves, pero providerAllowed sigue rechazando la descarga hasta que existan los requisitos. Los cuatro PNG públicos nuevos coinciden byte a byte con sus originales; decoders, worker y Android no se modifican. La auditoría --enforce mantiene 82/82 expedientes estructuralmente completos.
