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
- JetRoi, Marvs SSH y REG fallan sobre sus muestras aportadas. Se conservan errores reales; no se inventa una clave ni se devuelven datos de ejemplo.
- Ningún script original en decoders/Python/apps fue modificado. Se añaden únicamente adaptadores, inventario, fichas, copias públicas de iconos, controles y pruebas.

No ejecutado: actualización del VPS, nueva APK, publicación Play, extracción de credenciales ajenas, nuevos veredictos de integridad o pruebas autenticadas de proveedores que exigen datos no suministrados.

## Cierre de controles

Se ejecutaron además 151/151 pruebas Python de proveedores anteriores, aprobadas tras actualizar sus expectativas de inventario a 270 rutas. La auditoría F7-A0 con --enforce pasó con 82 expedientes estructuralmente completos, sin equivaler a validación remota. GitHub Actions compartido de caché pasó en 40a19fd. El primer preflight Android detectó una expectativa literal de COPY para V2Box ya desactualizada por la tanda anterior; se separa la instrucción COPY manteniendo todos los archivos y los 34/34 contratos de release pasan localmente. No se afirma una APK nueva compilada hasta que termine la ejecución remota.
