# F7-A0-P05 — Corpus APK/APKS y pruebas de límites

**Rama:** feat/nuevas-integraciones. **Estado:** PRUEBAS DE LABORATORIO, NO DESPLIEGUE DE PRODUCCIÓN. **No modificar** las 63 herramientas originales verificadas por Work.

## Objetivo

Probar archivos APK/APKS contra el entorno P03, de modo que el futuro servidor reciba archivos enviados desde SP-DECODE, seleccione métodos aprobados, conserve herramientas y dependencias entre trabajos, registre avances P04 y borre **solo** los residuos de un trabajo terminado después de confirmar el resultado. La funcionalidad completa Android -> subida -> ejecución -> respuesta sigue pendiente de A4/A5/A9.

## Corpus generado durante GitHub Actions, sin APK privados en Git

- `owned-signed.apk`: APK Android genuino **compilado y firmado por este proyecto en CI**, usando aapt2, javac, D8, zipalign, apksigner y clave temporal. Contiene manifiesto Android binario y `classes.dex` real de una clase de laboratorio que no interactúa con redes o permisos. **No es una APK VPN de un proveedor real**.
- `owned-container.apks`: archivo ZIP con `base.apk` anterior y una metadata de laboratorio. Es un paquete de test para el lector APKS actual, **no** un conjunto de splits instalable de bundletool.
- `negative-ratio.apk`: ZIP con compresión anormal; debe ser rechazado antes de que se invoque el analizador.
- Fixtures unitarios generados: rutas `../` y absolutas, duplicados, symlinks, APK sin manifiesto, XML sin compilar, ZIP corrupto, APKS sin base, APKS anidado inválido, límites de tamaño y número de entradas.
- Todos se crean en `RUNNER_TEMP`. **No** se guarda ni publica ningún APK, firma/keystore, DEX, JSON de análisis completo ni dato privado. Solo se sube un resumen sanitizado. No hay evidencias de tests sobre APK de terceros hasta recibir muestras autorizadas.

El registro de escenarios está en `analysis/platform/apk-tooling/p05_corpus.v1.json` y **no contiene binarios** ni hashes inventados de archivos privados.

## Nuevo gate de formato previo al análisis

`cloud/apk_analysis/input_gate.py` opera offline y sin importar módulos del descifrador. Inspecciona ZIP en modo solo lectura y rechaza:

| Límite P05 | Umbral de laboratorio |
|---|---|
| Archivo APK/APKS de entrada | 300 MiB |
| Entrada ZIP individual | 300 MiB |
| Datos expandidos acumulados (incluyendo interior APKS) | 600 MiB |
| Número total de miembros | 20,000 |
| Entradas APK dentro de APKS | 200 |
| Relación de compresión por entrada | Máximo 400:1 |
| Manifiesto binario Android | 8 MiB |
| Memoria de staging del APKS interior | 8 MiB; exceso pasa a archivo temporal |

Bloquea rutas de extracción inseguras, enlaces simbólicos/archivos especiales, entradas duplicadas, ZIP cifrado y manifiesto Android sin cabecera binaria. **No** confirma que el APK sea seguro, que su firma pertenezca al desarrollador original o que el DEX/ELF sea semánticamente válido. Los APKS solo admiten layouts con APKs en la raíz compatibles con el inspector actual; un layout no soportado debe rechazarse explícitamente sin afirmar compatibilidad.

**Importante:** un chequeo de cabecera del manifiesto no sustituye la validación binaria completa; el inspector de Work y la verificación de firma Android del flujo A4 completarán esa tarea.

## Prueba de contenedor real

Workflow optativo por cambio de herramienta/entrada y manual: `.github/workflows/f7-a0-p05-apk-lab.yml`.

1. Genera y firma el APK de laboratorio de forma efímera.
2. Ejecuta los 21 escenarios de límites con datos sintéticos.
3. Acepta el APK compilado y el APKS de prueba; rechaza el archivo de compresión patológica.
4. Construye la imagen Docker de P03 con las dependencias originales instaladas **durante el build**, no durante cada APK.
5. Ejecuta el preflight en contenedor sin red, solo lectura, UID 65532, capacidades eliminadas, PID 64, CPU 1.5 y memoria 3 GiB. El test `--allow-unprepared` NO asegura que JADX esté instalado; el precargador de recursos oficiales es un paso separado.
6. Ejecuta `scripts/apk_analysis/inspect_apk.py` **sin modificarlo** en ese contenedor, primero sobre APK y luego APKS. Verifica paquete, versionCode, DEX real y SHA-256 de la extracción.
7. El inspector genera resultados privados con modo 0600. El verificador del CI utiliza permisos de confianza del runner de laboratorio; no rebaja estos permisos para que las pruebas pasen.
8. Publica **solo** el resumen JSON sanitizado. Todos los APK y resultados del laboratorio se eliminan con el runner temporal.

En el host dedicado previsto para producción, **la imagen y la caché de JADX permanecen** entre peticiones; no se reinstalan paquetes ni se descargan recursos por APK. Los runners efímeros de GitHub Actions son laboratorios nuevos y pueden necesitar reconstruir imágenes durante CI: no constituyen aún prueba de persistencia entre reinicios de una VM real.

## Pendientes reales para cerrar F7-A0-P05

- APK de terceros **autorizados** y su hash/versión/alcance de consentimiento, procesados en VM separada: ninguna muestra privada en el repositorio.
- Un contenedor `.apks` auténtico de bundletool, con splits y firmas válidas, además de casos de múltiples APK; no confundirlo con el wrapper sintético de la prueba actual.
- Precarga real de JADX 1.5.6 con firma SHA-256, decompilación DEX y casos de corrupción/timeout. No modificar `decompile.py` probado por Work.
- Corpus ARM64 ELF válido y truncado; controles de ABI; heap, CPU, I/O y cuota de disco comprobados, no solo parámetros Docker.
- Aislamiento y persistencia de caché con reinicios de VM, trabajos simultáneos, cortes eléctricos simulados y recuperación desde checkpoints P04.
- A4/A5/A9: subida autenticada desde Android, seguridad del APK, política de ejecuciones, cola/reintentos, resultados cifrados y soporte humano.
- Los scripts ya existentes siguen sin aprobación desatendida global; P03 `execution_defaults=DENY` continúa vigente. El éxito de la prueba de laboratorio **no habilita** el servicio a usuarios.

## Ejecución y trazabilidad

```bash
python -m unittest discover -s tests -p 'test_a0_apk_input_limits.py' -v
python cloud/apk_analysis/input_gate.py /ruta/a/un.apk
# La compilación del laboratorio se ejecuta desde GitHub Actions en el runner con Android SDK y Docker.
```

Esta fase añade tests, herramientas de QA y documentación, **no** modifica `scripts/apk_analysis/`, `decoders/`, workers de descifrado ni pantallas Android. Mantener separados métodos verificados con APKs reales, tests del fixture propio y mecanismos únicamente estructurales.


### Evidencia real de GitHub Actions (laboratorio)

- [P05 APK Lab run 42325768902](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42325768902): **SUCCESS**. La compilación/firmado real del APK propio, el gate de 21 fixtures, construcción de imagen Docker y ejecución del inspector original en APK y APKS culminaron correctamente. Se comprobó `metadata.json`, packageId, versionCode y SHA-256 de `classes.dex`.
- [P05 JADX run 42326083344](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42326083344): **FAILURE** en precarga de JADX por espacio temporal de mantenimiento agotado (`Errno 28`); no por descifrado ni defecto del script original. Subfase corregida cambiando **únicamente** `apk-resource-preload.tmpfs` de 64 a 128 MB en `cloud/apk_analysis/compose.yaml`; entorno de análisis mantiene 64 MB, sin red ni privilegios. Nueva ejecución pendiente de verificar: [run 42326350743](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42326350743).
- [F7-A0 Method Evidence run 42325858523](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42325858523): **SUCCESS**, incluidas 21 pruebas adversas P05 agregadas al gate existente.

**Importante:** esos resultados de laboratorio no acreditan análisis de una VPN real externa, funcionamiento de APKs enviados desde Android ni soporte automático de todos los scripts de Work. El entorno real y P05 quedan sujetos a pruebas adicionales.


### Resultado final de las pruebas automáticas de P05

El workflow [F7-A0-P05 APK Lab — #42326911352](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42326911352) concluyó **SUCCESS**. Incluye 21 pruebas adversas de ZIP/APKS, generación/firmado de APK Android propio con DEX real, inspección del APK y wrapper APKS con el **script original**, precarga del JAR oficial **JADX 1.5.6 con SHA-256 comprobado**, reutilización en contenedores **sin red** y **JADX exit=0** al descompilar ese DEX propio. El resultado decompilado no contiene código ajeno y no se subió como artefacto.

El gate de evidencias [F7-A0 Method Evidence — #42326911348](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42326911348) concluyó **SUCCESS**, con **90 pruebas** distribuidas en 9 suites (11+6+7+9+5+7+20+4+21). Se verificó de nuevo 63/63 scripts originales intactos.

**Incidencias reales corregidas sin alterar herramientas originales:** (1) nuevo filtro ZIP interpretaba permisos sin tipo como symlink; (2) runner CI no leía archivos privados 0600; (3) precarga JADX agotaba tmpfs de 64 MiB, cambiado **solo mantenimiento** a 128 MiB; (4) JADX intentaba escribir configuración en rootfs de solo lectura, ahora el Dockerfile asigna HOME/XDG y `java.user.home` a `/tmp` temporal. El sandbox conserva UID 65532, red deshabilitada, `read_only`, límites y caché externa de solo lectura.

**Alcance:** APK firmado propio (real) y APKS de wrapper sintético; no es una certificación de APK VPN de terceros, split-set auténtico de bundletool, ELF ARM64 ni análisis automático desde Android. **P05 permanece PARCIAL** hasta esas pruebas y el despliegue aislado real A4/A5/A9.


## Extensión de P05 — inyección de fallos y recuperación (rama, sin producción)

Se añadieron `scripts/ci/p05_sandbox_faults.py`, `tests/test_a0_p05_failure_recovery.py` y aserciones explícitas de formato en `tests/test_a0_apk_input_limits.py`. Se conectaron al workflow **F7-A0-P05 APK Lab**, y la suite de recuperación al gate **F7-A0 Method Evidence**. Las nuevas pruebas NO alteran ninguna de las 63 herramientas ni los descifradores.

| Caso | Qué se comprueba | Estado |
| --- | --- | --- |
| Sandbox Docker | UID 65532, capacidades vacías, rootfs de solo lectura, sin red, /tmp no ejecutable; cuota CPU/PID | CI en validación |
| Memoria | Cgroup real de 96 MiB rechaza presión de páginas (se espera exit 137) | CI en validación |
| Disco | tmpfs real de 8 MiB produce ENOSPC bajo presión acotada | CI en validación |
| Tiempo e interrupción | Detención forzada de contenedor de prueba tras deadline y comprobación de no dejar contenedor huérfano | CI en validación |
| Recursos | Comprobar que JADX con SHA-256 sigue disponible desde volumen de solo lectura y sin red después de fallos | CI en validación |
| Host / SIGKILL | Proceso propio interrumpido; estado IN_PROGRESS, entrada y recursos permanecen | CI en validación |
| Estado / ENOSPC | Fallo atómico de escritura simulado: el job no avanza ni se limpia | CI en validación |
| Soporte humano | AWAITING_HUMAN nunca pasa al recolector automático | CI en validación |
| Recibo y limpieza | Tras comprobación de integridad por oráculo de test y checkpoint confirmado, se elimina solo el workspace; conserva el resultado y la caché | CI en validación |
| Formatos | .apk y .apks admitidos por gate; .zip y .xapk rechazados explícitamente | CI en validación |

El test del oráculo de persistencia es **sintético**: NO acredita almacenamiento cifrado ni comprobación de propietario/tenant, que siguen siendo requisitos A4/A5. La inyección Docker es una prueba real de límites **en el runner efímero de GitHub**, NO certifica rendimiento sostenido ni persistencia de una VM dedicada. La CPU se inspecciona mediante cgroup cuando está disponible, no mediante benchmark estable. El disparador usa exclusivamente código/artefactos propios de CI, sin ejecutar APK de usuarios ni métodos VPN.

La extensión continúa como **PARCIAL** hasta que existan pruebas verdes verificadas, corpus de VPN externas con autorización/consentimiento verificable, APKS real de bundletool, ELF ARM64, estrés concurrente/reinicio de host y flujo Android→A4→A5→A9 con resultados cifrados y soporte humano. Se prohíben merge a main y despliegue de producción en este avance.
