# SP-DECODE F7-A8 — continuidad de sesión, arnés de análisis y UX beta

**Rama:** `feat/nuevas-integraciones`. **Ámbito:** analizador privado APK/APKS.
**No implica publicación en Google Play ni autorización de un método de descifrado.**

## Evidencia inicial del informe de prueba

Entrada de referencia aportada por el operador: APKS 22,493,144 bytes, 4 APK internos,
3 DEX/7 ELF; JADX Lite agotó memoria en el intento monolítico y recuperó referencias
en 2/3 DEX tras varios reintentos. No hay métodos de terceros validados ni extracción
de credenciales; cualquier escenario de descifrado sigue `PENDING`.

## Cambios F7-A8

### 1. Continuidad Android
- `CloudApkQaClient` mantiene el checkpoint cifrado, token y progreso remoto.
- El corte deliberado del segmento de WorkManager a los seis minutos es ahora
  `Result.retry()` **sin registrar error visible de desconexión**.
- Backoff lineal acotado del worker, reanudación al recuperar la red y verificación
  del `nextChunk` suministrado por el servidor. La reconexión manual continúa
  disponible ante problemas reales; no se crean cargas duplicadas.
- Este cambio **sí requiere una APK beta nueva**; una actualización solo de VPS
  no puede modificar el WorkManager instalado en el teléfono.

### 2. Subfases realmente observadas
- Metadatos del paquete desde manifiesto binario validado.
- DEX, métodos y bytecode, y biblioteca nativa ELF (cuando estén presentes).
- Descompilación estática, recuperación DEX cuando corresponde y correlación
  de evidencia criptográfica.
- Latido público del servidor cada 40 segundos durante `PROCESSING`: mantiene
  el TTL sin crear una sesión o una fase ficticia. Los eventos son persistentes,
  ordenados y limitados; el cliente solo interpreta códigos de una lista cerrada.
- No reportar como descifrado real las referencias a `Cipher`, nombres de métodos
  ni bytes criptográficos. El indicador `methodValidated` permanece falso.

### 3. Perfil JADX Lite adaptado a multidex
- Si la inspección inicial confirma al menos dos DEX válidos y un total de DEX
  >=16 MiB, omite el paso monolítico que causaba presión de memoria en la prueba.
- Prioriza `fallback` en DEX >=6 MiB, y conserva modo `simple` en DEX
  menores; máximo 120 segundos por DEX grande.
- Preserva cualquier fuente recuperada, no ejecuta APK ni C++ nativo, no extrae
  secretos a los reportes. Perfil aislado de 1 proceso Java y 1 CPU.
- La política de seguridad no permite ejecutar ni instalar dinámicamente
  herramientas de terceros aportadas por un APK. Ghidra sigue deshabilitado
  en la VPS de 3.7 GiB.

### 4. Arnés y 63 herramientas históricas
- `analysis/platform/apk-tooling/tool_sources.v1.json` mantiene las 63
  rutas de investigación, que incluyen herramientas para proveedores concretos,
  probes de red, oráculos y emulación. **No son 63 pasos universales seguros.**
- El arnés `qa_tool_harness.py` informa 63 scripts inventariados y
  `researchScriptsAutoExecuted: 0`. No simula una ejecución de scripts no revisados.
- Ejecuta correlaciones de cinco adaptadores *built-in*: estructura de APK,
  tablas DEX y code items, ELF, referencias estáticas de JADX cuando se haya
  intentado y correlación de clases, métodos y referencias. El resultado es
  `analysis.harness` con candidatos acotados y evidencia por fuente.
- Para ejecutar un script de los 63, antes se requiere auditoría individual de
  imports y dependencias, ausencia de red/credenciales, ruta de entrada aislada,
  límite de CPU/memoria/tiempo y evidencia reproducible. No saltar el policy gate.

### 5. Identidad y exportación de resultados
- `appIdentity.packageName` se extrae del `AndroidManifest.xml` binario.
- `appIdentity.appName` solo se establece con etiqueta literal del manifiesto
  o resolución estática de `resources.arsc` (si es una cadena simple legible).
  Si no puede resolverse, se muestra el paquete o el nombre del archivo; nunca
  se inventa un nombre de aplicación.
- El historial cifrado sigue admitiendo registros previos y guarda los campos
  nuevos de forma opcional. El envío activo identifica como mínimo el archivo.
- `Exportar JSON` usa `JsonReader`/`JsonWriter` para escribir sangría de
  dos espacios en flujo, sin árbol JSON adicional. El nombre sugerido utiliza
  `appName` o `packageName` y marca temporal para evitar sobrescrituras.
- No se modifica el JSON fuente recibido ni el resultado almacenado. La función
  de exportación requiere APK beta nueva.

## Validación y QA pendientes

Los tests sintéticos de F7-A8 validan el arnés, clasificación deny-by-default,
manifiesto AXML y nombres de recursos ARSC. Los workflows de GitHub Actions de
esta rama deben confirmar compilación real Android/HPKE, pruebas del servidor,
Dockerfile y regresión global. Hasta estar en verde, no afirmar certificado
de producción.

En la VPS privada, repetir una prueba con el mismo APKS aportado por el operador:
verificar latidos y subfases, que la app beta no requiera botón `Reconectar`
ante el corte habitual del worker, fuente parcial persistida, desempeño del
DEX grande, `appIdentity` cuando resuelva y exportación JSON formateada.

## Despliegue **solo después de CI verde**

```bash
sudo spdecode backup
sudo spdecode update all feat/nuevas-integraciones
sudo spdecode apk-qa status
sudo spdecode apk-qa enable
sudo spdecode apk-qa enable-lite
sudo spdecode status
```

`update all` puede reconstruir servicios compartidos del VPS. No es un
despliegue aislado de QA y no sustituye la APK beta nueva. El analizador sí
está restringido al cliente beta que contiene sus pantallas y operaciones.
