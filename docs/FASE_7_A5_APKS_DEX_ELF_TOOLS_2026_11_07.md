# F7-A5 — análisis estático progresivo de APK/APKS, DEX y ELF

Rama: `feat/nuevas-integraciones`. La subida de 100 MB, SHA-256, HPKE, checkpoints, token de capacidad interno y una sola tarea activa se conservan.

## Capas integradas
1. El **laboratorio de 320 MB** (perfil predeterminado de la VPS) examina todos los APK internos de APKS, metadatos y tablas DEX, descriptores de clases, nombres candidatos de métodos, encabezados ELF, bibliotecas importadas y firmas criptográficas referenciadas. Se revisa el archivo real recibido, no solo los nombres de los splits. Las clases/métodos ofuscados pueden continuar siendo ilegibles y los metadatos NO equivalen a reconstrucción de código.
2. El adaptador `qa_tooling.py` contiene invocaciones restringidas a JADX **1.5.6** con JAR SHA-256 validado y, si Ghidra ya está instalado en una imagen aislada, a su `analyzeHeadless` con reporte automático de conteo de funciones. Ninguno ejecuta el APK.
3. **Solo un contenedor con límite efectivo de 3 GiB** y JDK/JAR verificados puede activar el modo de herramientas. No se puede habilitar sin configuración y recursos adecuados. Un host de ~1 GiB NO debe hacerlo. Para probar en un host con al menos 4 GiB, preparar la imagen de herramientas y configurar `SPDECODE_APK_QA_DOCKERFILE=cloud/apk_analysis/Dockerfile.qa-tools`, `SPDECODE_APK_QA_MEM_LIMIT=3072m` y `SPDECODE_APK_QA_TOOL_MODE=enabled` en el archivo privado de entorno. El contenedor avanzado debe mantenerse aislado de secretos, Docker socket y el worker de descifrado VPN.
4. Para usar Ghidra hace falta añadir una distribución oficial revisada, fijar su versión/hash y su ruta `/opt/ghidra` **en la imagen avanzada**. El adaptador está escrito, pero la distribución NO se instala automáticamente ni está validada. Nunca afirmar `ghidraExecuted=true` si el proceso no se ejecutó y entregó un informe.
5. El resultado lleva `APK_STATIC_QA_DEEP_V2` y `COMPLETED_PARTIAL`: indica análisis de metadatos real, **no** que se haya identificado/verificado un descifrador VPN. Las referencias AES/GCM, EVP, etc. son referencias detectadas; no demuestran algoritmo efectivo ni claves extraídas.

## Verificación requerida
- Tests sintéticos de APK/APKS realistas con DEX y ELF verdaderamente inspeccionados.
- Prueba real firmada Android → VPS de un APKS autorizado: verificar `dexParsed`, `elfParsed`, `cryptoIndicators`, estados de toolchain y coherencia de `codeExecuted`.
- En un servidor de al menos 4 GiB: prueba end-to-end de la imagen pesada con JADX verificado; Ghidra requiere distribución oficial, licencia y prueba de seguridad.
- El VPS actual **no se ha actualizado** durante esta integración. No iniciar herramientas pesadas en un host sin RAM suficiente.
