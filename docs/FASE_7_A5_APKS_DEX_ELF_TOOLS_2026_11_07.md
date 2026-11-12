# SP-DECODE F7-A5 — APK/APKS, código Dalvik, JADX y Ghidra aislados

**Rama:** `feat/nuevas-integraciones`. **Ámbito:** únicamente Cloud/VPS. Ningún cambio de Android, firma, APK Release o AAB forma parte de esta continuación. El cliente 1.1.27 b42 ya recibe informes `APK_STATIC_QA_DEEP_V2`.

## Flujo operativo

1. La app sube el archivo completo por HPKE V2 en fragmentos, con hash SHA-256, reanudación, consentimiento y máximo de 100 000 000 bytes.
2. `apk-qa` comprueba el archivo **completo** antes de iniciar inspección. En su contenedor de **320 MB**, lee todos los APK de un APKS, cabeceras/tablas DEX, `class_data_item`, `code_item` de métodos candidatos, ELF/so, símbolos, importaciones, assets y referencias criptográficas. No ejecuta código aportado.
3. Si el worker experimental está activado, el receptor envía los bytes **verificados** al worker privado por un protocolo HMAC independiente y streaming. Se valida otra vez SHA-256 y la estructura del paquete. No se comparte el token Web→QA, llaves HPKE, journals, base de datos, socket Docker ni endpoints públicos.
4. `apk-tools` usa JADX y Ghidra oficialmente fijados y ejecutados **sin red durante los trabajos**. Solo entrega resúmenes técnicos: archivos Java procesados, posibles referencias a APIs criptográficas, clases/métodos candidatos, conteos de funciones y símbolos relevantes. No entrega contraseñas, fuentes Java completas, secretos, ni asegura que haya reconstruido un método de descifrado.
5. Se eliminan los archivos de trabajo al terminar. El informe persiste en la cola de QA y sigue sujeto a su plazo de retención. La recepción no permite un segundo APK hasta que el primero alcance un estado terminal.

## Toolchain fijada y cargada solo al construir imagen

- **JADX 1.5.6**, JAR SHA-256: `fe3e12c45acf75f92369685fd02d1d7a7323385dc725680a9b98a0dac0ea554b` (script propio `scripts/apk_analysis/decompile.py`).
- **Ghidra 12.1.4 PUBLIC, 2026-09-21**: ZIP original oficial `ghidra_12.1.4_PUBLIC_20260921.zip`, SHA-256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`; licencia Apache-2.0; compatible con **JDK 21**. URL: https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build.
- Dockerfile `cloud/apk_analysis/Dockerfile.qa-tools` instala JDK21, Python3, JADX y Ghidra verificando la distribución; genera además una huella local del lanzador `analyzeHeadless` para comprobarlo antes de ejecutarlo. Los binarios se conservan en capas Docker y **no** se reinstalan por APK.
- Scripts propios de análisis: `qa_deep.py`, `qa_dex_bytecode.py`, `qa_jadx_refs.py`, `qa_tooling.py`, `SpDecodeGhidraReport.java`. No se modifican los 63 scripts históricos de investigación.

## Recursos y aislamiento

**No activar el worker pesado en el VPS actual de aproximadamente 1 GB.** El comando de activación exige **al menos 8 GB de RAM y 8 GB libres** y falla sin modificar configuración si no los detecta. El contenedor de herramientas tiene límite de 4 GB de RAM y espacio temporal de hasta 1 GiB, usuario 65532 sin root, sistema de archivos read-only, Docker sin capacidades y una **red interna sin puertos publicados**. JADX/Ghidra pueden tardar varios minutos, especialmente en ELF grandes. Los procesos se detienen con su grupo completo al exceder el timeout.

La ejecución de herramientas es experimental, no una autorización general de los 63 scripts de investigación. Por defecto, la ruta Cloud usa únicamente el inspector liviano. El perfil pesado está aislado y es **opt-in** hasta pasar pruebas y revisión operativa.

### Actualización normal (VPS de 1 GB, sigue usando inspección DEX/ELF)

~~~bash
sudo spdecode update all feat/nuevas-integraciones
sudo spdecode apk-qa enable
sudo spdecode apk-qa status
~~~

### Activar análisis profundo (solo después de aumentar capacidad)

~~~bash
sudo spdecode apk-qa enable-tools
sudo spdecode apk-qa status
~~~

La CLI crea y almacena la credencial interna entre receptores/worker sin solicitar tokens ni registros de dispositivos. El segundo comando instala/construye las dependencias una única vez y deja servicios ejecutándose en segundo plano con Docker. La **APK Android permanece igual**.

## Salida y criterios de evidencia

- `inventory.dexHeaders[].methodCodeEvidence` contiene nombre de clase y método, tamaño y SHA-256 de bytecode Dalvik cuando el `code_item` existe. **No** constituye pseudocódigo o un descifrador funcional.
- `analysis.tooling.jadx.candidateCallSites` procede de archivos fuente reales producidos por JADX, si `jadxExecuted=true`. Son referencias estáticas a llamadas; no valores de claves ni métodos validados.
- `analysis.tooling.ghidra.candidateFunctions` procede de símbolos detectados por Ghidra, si `ghidraExecuted=true`. Un símbolo de método no prueba su semántica.
- Estado global `COMPLETED_PARTIAL` y `vendorMethodValidated=false` mientras no existan pruebas positivas/negativas reproducibles con una configuración autorizada. `nextStages` conserva solo las etapas no ejecutadas.
- Ghidra no se limita a inventariar el ELF: se invoca `analyzeHeadless`, pero todavía no se ofrece una descompilación completa de pseudocódigo en el resultado.

## Pruebas y pendientes

- `tests/test_f7_apk_qa_deep.py`: APKS anidados, tablas, criptografía referenciada y ELF.
- `tests/test_f7_apk_qa_jadx_refs.py`: referencias reales en código Java y exclusión de bibliotecas comunes.
- `tests/test_f7_apk_qa_tool_rpc.py`: autenticación HMAC, SHA completo, nonce anti-replay, limpieza y ruta privada.
- `tests/test_f7_apk_qa_tooling_policy.py`: separación de red, pines y políticas.
- `.github/workflows/f7-apk-tools-image.yml`: compila los binarios originales fijados, ejecuta JADX y Ghidra contra **muestras propias** sin acceso de red, sin generar APK/AAB.

**Estado antes de CI:** código integrado en rama; no equivale a despliegue ni test Android→VPS→worker avanzado. Requiere CI verde y una máquina de pruebas con recursos suficientes. No afirmar métodos VPN descifrados por encontrar referencias AES, ChaCha, JNI o nombres parecidos a "decrypt".
