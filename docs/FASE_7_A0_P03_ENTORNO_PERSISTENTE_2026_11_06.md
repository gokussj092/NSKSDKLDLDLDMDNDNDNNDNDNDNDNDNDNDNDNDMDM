# F7-A0-P03 — Entorno APK dedicado, caché persistente y limpieza por trabajo

**Rama:** `feat/nuevas-integraciones`. **Estado:** IMPLEMENTACIÓN DE BASE + PRUEBAS AISLADAS; **NO DESPLEGADO, NO HABILITADO PARA USUARIOS**.

## Necesidad funcional aprobada

El usuario seleccionará o compartirá un APK desde SP-DECODE. El servicio deberá **recibirlo y analizarlo automáticamente**, conservar resultados para entrega e intervención humana cuando sea necesaria y eliminar después el APK y sus residuos. **No** deberá reinstalar las 7 bibliotecas Python ni descargar JADX para cada APK.

### Flujo previsto de extremo a extremo

```text
Android SP-DECODE
  -> A1/A2 autenticación y consentimiento + A3 reserva de crédito
  -> A4 subida fragmentada reanudable, validación del APK/hash, almacenamiento seguro
  -> A5 cola persistente y orquestador
  -> sandbox aislado POR TRABAJO + scripts existentes seleccionados
  -> checkpoint/resultados persistidos y verificados fuera del espacio temporal
  -> respuesta a Android / escalado humano (A6)
  -> limpieza automática SOLO después de confirmación durable de resultado
```

**Este flujo todavía NO está conectado**. P03 prepara reglas y recursos del entorno; A1–A5 y A9 deben implementar autenticación, upload, cola, ejecución y pantallas. No afirmar soporte real de APK end-to-end por existir Docker y tests de fixtures.

## Recursos que deben sobrevivir al análisis

| Ruta/componente | Persistencia | Condiciones |
|---|---|---|
| Imagen de herramientas `spdecode-apk-tools:p03` | Docker layers | Instala dependencias fijadas **en build**, no por cada APK |
| `spdecode-apk-tools-cache` | Volumen Docker nombrado | Conserva el JADX JAR **con checksum verificado** y futuros recursos confiables, nunca APKs de usuarios |
| `/var/lib/spdecode/apk-analysis/jobs/<uuid>` | Temporal por APK | Solo input/scratch/output-staging, permisos 0700; contenido sensible que se purga con recibo terminal |
| `/var/lib/spdecode/apk-analysis/state/<uuid>.json` | Estado host exclusivo | Documento mínimo de resultado ya persistido/cierre, **no se monta al sandbox** |
| Almacén de resultados A4/A5 | Persistencia separada cifrada | No borrar resultados que el usuario aún necesita descargar |
| APK en soporte humano A6 | Retención temporal controlada | No borrar hasta solución o cierre explícito; cumplir consentimiento y política de retención |

**Un volumen compartido de herramientas es solo lectura en trabajos reales.** Solo el perfil `apk-resource-preload` tiene acceso de escritura para descargar recursos verificados **en modo mantenimiento**. El perfil de análisis no tiene red, acceso al socket Docker, puertos, credenciales ni volúmenes del decoder-worker actual.

## Entorno separado y límite de recursos

- Directorio del entorno: `cloud/apk_analysis/`; archivo `compose.yaml` **independiente** de `cloud/compose.yaml`. No se inicia con `spdecode update all`.
- Docker: usuario no root **65532:65532**, rootfs solo lectura, capacidades eliminadas, no-new-privileges, PID máximo 64, CPU 1.5, memoria **3072 MB**, tmpfs limitada y red deshabilitada en sandbox.
- **No** se monta `/var/run/docker.sock` ni se conectan credenciales/Redis/HPKE/administración del servidor.
- Para instalar nuevos paquetes o binarios verificados se cambia y reconstruye la imagen durante mantenimiento, **no por análisis**. No se actualizan los scripts o pines funcionales por iniciativa propia.
- El proceso actual de descifrado VPN sigue en `decoder-worker` sin modificación.
- La máquina del usuario había tenido aproximadamente **1 GB de RAM**: no se recomienda ejecutar el análisis con JADX en ese mismo tamaño de VPS (la implementación existente pide `-Xmx2200m`). Para pruebas reales, utilizar **un host/VM aislado con al menos 4 GB de RAM**, dimensionando disco y concurrencia. Es una recomendación inicial, no prueba de capacidad definitiva.
- El límite de almacenamiento por trabajo todavía requiere cuotas Linux/sistema de archivos comprobadas en A4/A5. **No** se debe dar por garantizado un tope de disco simplemente por definir un campo en JSON.

## Implementación P03 existente

1. `cloud/apk_analysis/workspace.py`: gestor de ciclo de vida host-side `WorkspaceStore`. Crea UUID y carpetas privadas de entrada/trabajo/staging, separa cache/state, impide traversal y raíz/scratch symlink, y conserva trabajo pendiente.
2. `result_persisted(...)`: **solo el servidor confiable** puede llamarlo **después** de comprobar un resultado durable en almacenamiento externo. Guarda el recibo host-only y limpia automáticamente el trabajo. No recibe instrucciones del APK ni del contenedor de análisis.
3. `close_without_result(...)`: permite cerrar un caso sin solución y limpiar tras una decisión final; corresponde a la posterior política de créditos y soporte.
4. `reap_completed()`: recupera borrados interrumpidos por caída/reinicio, **sin tocar trabajos en curso o pendientes de soporte humano**. Los trabajos abandonados sin estado terminal deberán tratarse mediante retención A4/A6.
5. `runtime_preflight.py`: confirma versiones directas instaladas, disponibilidad Java y hash SHA-256 del JAR de JADX; falla si falta el recurso necesario.
6. `execution_policy.v1.json`: DENY por defecto para las 63 herramientas. Solo `inspect_apk.py` y `decompile.py` aparecen como **candidatos pendientes de P05** con SHA de fuente existente; ambos están deshabilitados hasta revisión real.
7. `Dockerfile`: imagen dedicada con Python 3.12, JRE 17, Cairo y dependencias del `requirements.txt` vigente. Copia solo las dos herramientas candidatas, sin introducir credenciales, cachés ni APK en el contexto de build.
8. `Dockerfile.dockerignore`: lista blanca de fuentes que puede entrar al contexto Docker.
9. `compose.yaml`: perfiles de preflight offline y precarga separada. Ninguno inicia servicios de producción ni publica puertos.
10. `scripts/ci/check_apk_analysis_policy.py` y sus tests: impiden habilitar ejecución desatendida, abrir red, cambiar hashes, borrar antes de resultado o introducir montajes privilegiados accidentalmente.

## Comandos para un HOST DE PRUEBAS aislado (NO ejecutar en el VPS de producción)

```bash
# Preparar imagen una vez por cambio de toolchain:
docker compose -f cloud/apk_analysis/compose.yaml build apk-runtime-preflight

# Precargar/reutilizar JADX oficial con comprobación de SHA-256.
# Solo necesita red durante mantenimiento; en sucesivas ejecuciones usa caché.
docker compose -f cloud/apk_analysis/compose.yaml run --rm apk-resource-preload

# Preflight sin red, con caché verificada; no procesa APKs:
docker compose -f cloud/apk_analysis/compose.yaml run --rm apk-runtime-preflight
```

**No realizar estos pasos en producción todavía**: faltan locks transitivos (P01), compatibilidad real de la imagen, verificación del aislamiento Docker y las fases A4/A5/A9. Docker CI solo comprueba la sintaxis y reglas, **no construye ni ejecuta la imagen** en P03.

## Pruebas implementadas y siguientes criterios

- Workspace: crear dos trabajos, conservar caché al limpiar uno, persistir resultados fuera, bloquear borrado en curso/soporte, rechazar traversal y symlinks, recuperación tras crash, checks de recibo.
- Política: **denegar por defecto**, hashes de fuentes existentes, sin red ni privilegios, ningún auto_run, imagen/Compose sin instaladores por trabajo.
- Preflight: rechazar versión de dependencia equivocada, falta/corrupción de recurso JADX y aceptar un recurso que coincide con hash.
- Docker Compose: `docker compose config --quiet` y pruebas de auditoría en CI.

**Pendiente P03 / fases posteriores:** builds reales en VM de pruebas; límites efectivos CPU/RAM/disco y seccomp; programa selector de herramientas por evidencia; aprobación de scripts para ejecución; flujo automático A4/A5 con cola, retransmisiones, checkpoint durable, validación binaria APK/APKS, entrega o escalado a humano; integración Android. Las herramientas existentes se conservan sin cambios y se habilitarán únicamente tras test y revisión individual.

## Referencias
- `analysis/platform/apk-tooling/execution_policy.v1.json`
- `docs/FASE_7_A0_P02_MAPA_HERRAMIENTAS_2026_11_06.md`
- `docs/FASE_7_A0_P01_AUDITORIA_DEPENDENCIAS_2026_11_06.md`


### Resultados verificados en GitHub Actions (P03)

La ejecución [F7-A0 Method Evidence #42318706983](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42318706983) concluyó **SUCCESS**. Las suites: **11** pruebas de política de evidencias, **6** de dependencias, **7** de mapa P02, **9** de workspace aislado, **5** de recursos persistentes/preflight y **7** de política de ejecución = **45 pruebas aprobadas**.

Los verificadores indicaron **63/63 scripts originales intactos**, 2 perfiles candidatos en política, **0 aprobados para ejecución automática**, caché persistente separada y política de limpieza tras recibo de resultados. La comprobación `docker compose ... config --quiet` finalizó correctamente.

**Alcance exacto:** son pruebas de fixtures y contratos. No se compiló la imagen Docker, no se ejecutaron APK reales y no se habilitó el análisis APK desde Android ni el VPS. Esas condiciones siguen pendientes para A4/A5/A9.
