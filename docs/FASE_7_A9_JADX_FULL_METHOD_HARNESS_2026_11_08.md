# F7-A9: JADX completo y arnés estático de métodos en el servidor

## Alcance y comportamiento

La activación existente `spdecode apk-qa enable-tools` instala el perfil completo:
JADX 1.5.6 (JAR completo fijado por SHA-256), modo `auto`, JDK 21 y Ghidra
12.1.4 (ZIP oficial verificado en la construcción). Antes, incluso el perfil
completo invocaba `simple`, y Compose no transmitía la activación de Ghidra.

No se modifica ni compila Android. El código de la aplicación analizada nunca se
ejecuta. Los procesos de análisis trabajan sin red en el servicio privado
`apk-tools`, sin puertos públicos, con usuario sin privilegios y almacenamiento
temporal separado. El servicio conserva un solo trabajo activo.

El modo Lite anterior sigue disponible únicamente como comando explícito de
compatibilidad. `enable-tools` reemplaza cualquier configuración Lite anterior,
conserva el secreto privado y activa Ghidra. No se hace sustitución automática por
Lite cuando falta memoria.

## Presupuestos efectivos

El CLI selecciona recursos según la memoria física REAL del servidor. El trabajador
elige su presupuesto usando el límite REAL de memoria del contenedor (cgroup).

| Recurso | Servidor desde 8 GB | Servidor cercano a 12 GB y 4 núcleos |
| --- | --- | --- |
| Memoria máxima del contenedor | 4096 MiB | 8192 MiB |
| CPU máxima configurada | 1.8 | 3.0, si hay al menos 4 CPU |
| Heap JVM de JADX | 1800 MiB | 4096 MiB |
| Hilos de JADX | 2 | 3 |
| Modo principal | auto | auto |
| Presupuesto de JADX con recuperación | 420 s | 900 s |
| Presupuesto total de herramientas | 840 s | 1680 s |
| DEX seleccionados para recuperación | hasta 16 | hasta 32 |
| Bibliotecas nativas seleccionadas | hasta 8 | hasta 16 |
| Tamaño máximo por biblioteca | 64 MiB | 64 MiB |

El perfil grande se activa con MemTotal >= 11 000 000 KiB; el trabajador necesita
un límite de contenedor >= 7 GiB para utilizarlo. El CLI exige al menos 3 GB
actualmente disponibles y 8 GB libres en disco (15 GB para el perfil grande).
Estos son límites de selección, no una garantía de analizar todo un binario.
Se mantiene el límite de carga de 100 MB y las barreras del validador ZIP/APKS.
La recuperación mantiene sus límites adicionales de 40 MiB por DEX y 96 MiB
extraídos por trabajo. Todos los análisis son secuenciales; no se reservan 8 GB
a cada herramienta simultáneamente.

## Evidencia nueva que entrega el arnés

- `analysis.tooling.toolDistribution = JADX_FULL`, perfil de recursos y modo
  efectivo en `analysis.tooling.jadx.decompilationMode`.
- `analysis.tooling.jadx.methodRecipes`: métodos presentes en código realmente
  generado por JADX, clase, líneas, SHA-256 del cuerpo, roles de API, algoritmos
  permitidos y parámetros numéricos observados. Las llamadas locales incluyen
  identificadores de origen/destino; la resolución de sobrecargas queda pendiente.
- La recuperación por DEX usa `auto` y después `fallback`, respeta el plazo global,
  conserva salida parcial y deduplica los métodos por clase/nombre/hash.
- Ghidra enumera funciones y descompila hasta 12 candidatos por biblioteca con
  hasta 5 segundos por función. Exporta hash y cantidad de líneas del C y
  referencias a funciones con nombres relevantes; no exporta el código.
- `analysis.harness` relaciona evidencia DEX, métodos JADX y propietarios JNI.
  Los 63 scripts históricos continúan inventariados. No se ejecutan a ciegas:
  algunos son específicos de versiones, requieren credenciales o ejecutan código.
- El estado avanzado solo indica completado si JADX terminó y Ghidra cubrió los
  ELF seleccionables sin faltantes; un tiempo agotado conserva estado parcial.
  El informe raíz conserva el contrato anterior `COMPLETED_PARTIAL`.

Ningún candidato se convierte automáticamente en un descifrador validado.
`methodValidated`, `vendorMethodValidated` y `codeExecuted` permanecen falsos.
No hay prueba de grafo de llamadas global, análisis dinámico, reconstrucción
automática completa de métodos ni resolución garantizada de ofuscación.
Los nombres y las llamadas locales son referencias estáticas.
Claves, contraseñas, URLs privadas, fuentes y logs no se incluyen en los informes.
La extracción está acotada a 64 métodos, 96 relaciones y 64 MiB de fuentes;
cada archivo Java admite hasta 256 KiB, excluyendo bibliotecas de framework.

## Actualización del VPS por el operador

Tras revisar los cambios y sus pruebas, en el servidor ya provisionado:

```bash
sudo spdecode update all feat/nuevas-integraciones
sudo spdecode apk-qa enable-tools
sudo spdecode apk-qa status
```

Si APK QA todavía no está habilitado, ejecutar antes `sudo spdecode apk-qa enable`.
La activación construye las imágenes del servidor, comprueba la salud de ambos
servicios y restaura la configuración anterior si falla. No construye APK/AAB.
El siguiente informe debe mostrar `JADX_FULL`; los informes históricos no se
reescriben. Las etiquetas de la versión Android instalada pueden seguir diciendo
JADX Lite hasta una actualización futura del cliente, fuera de este cambio.

Estos comandos son instrucciones reproducibles; no se ejecutaron contra el VPS
desde esta sesión. No se cambió producción ni se realizó merge a main.

## Transporte del informe completo

El antiguo gateway rechazaba informes mayores de 128 KiB. Se amplía a 2 MiB
para el resultado completo (inventario y herramientas), con lectura limitada por
bytes UTF-8 durante el streaming. El RPC privado de herramientas admite hasta
512 000 bytes. HPKE ya admite respuestas mayores; no se cambia su seguridad ni
la aplicación Android. Un resultado dentro de los límites se devuelve íntegro.

## Verificación reproducible

1. `.github/workflows/f7-a7-server.yml`: compileall, sintaxis Bash, pruebas de
   perfiles, parser de métodos, recuperación, RPC, configuración idempotente,
   ciclo completo del servicio QA y límites; valida Docker Compose. Prueba también
   el gateway del informe completo y las regresiones de TunnelDoom. Conserva una
   regresión offline del antiguo perfil Lite.
2. `.github/workflows/f7-apk-tools-image.yml`: construye la imagen completa
   fijada, compila muestras Java/ELF propias y ejecuta JADX `auto` y Ghidra
   reales sin red. Verifica recetas, referencias locales y hash del C nativo.
   No crea APK/AAB ni publica muestras de terceros.
3. La integración de TunnelDoom tiene expediente independiente en
   `analysis/com.tunneldoom.http/432/`. La prueba real del catálogo del
   2026-11-09 UTC está en `generated/current-proof.json`.

Los adjuntos JSON de esta conversación no pudieron leerse porque el entorno
local de ejecución estaba desconectado. No se afirma validación de Litron Pro
ni de las APK de esos informes. Las muestras propias prueban el arnés; cada
método de terceros requiere su propio expediente y oráculo independiente antes
de declararse validado.

## Resultados observados de esta revisión

- Código del servidor validado en `b2be8c44ad57ef6d702bd39ef2a757f7f986d385`.
- [Pruebas del servidor y gateway](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42564695453):
  72 pruebas Python y 20 pruebas Node aprobadas; sintaxis Bash, Docker Compose,
  construcción de imagen y regresión del perfil Lite anterior también aprobadas.
- [JADX completo y Ghidra reales](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42564558288):
  aprobado sobre muestras Java/ELF propias, con el código de herramientas de
  `5cbb259ca38fae927f12d145edd1b9297aa71cf2` (sin cambios posteriores en ese código).
  Confirmó modo auto, recetas de métodos, llamadas locales y hash de C nativo.
- [Gate P06 del PR](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42564701372):
  aprobado después de enlazar también el decoder operativo de catálogo con el
  expediente de TunnelDoom build432.
- [Prueba remota de TunnelDoom](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42562741781):
  HTTP 200, catálogo versión 496, 382 servidores y 4966 campos cifrados;
  JSON completo comparado con el oráculo independiente Java/JCA.

Estas verificaciones no son un despliegue ni una prueba del VPS del operador.
