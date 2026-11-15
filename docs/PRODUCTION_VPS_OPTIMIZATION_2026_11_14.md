# SP-DECODE Cloud — migración y optimización de producción

Fecha: 2026-11-14.
Rama: `ci/unity-ads-online-qa`.
Revisión de producción durante la migración: `0a4a3cad3afd35a9ac1703510ce34a53c040978e`.

## Estado validado

Migración a Ubuntu 26.04 LTS x86_64, 12 GB nominales de RAM (~11 GiB visibles), 6 vCPU y 96 GiB de disco utilizable. Se mantuvo el proyecto Compose `spdecode`, Nginx, los dominios spdecode.xyz, api.spdecode.xyz y panel.spdecode.xyz, el transporte HPKE V2 y la política V1 deshabilitada.

Se transfirieron siete imágenes Docker, siete volúmenes persistentes, configuraciones, certificados y un RDB de Redis. PostgreSQL fue respaldado lógicamente y copiado físicamente después de detenerlo. La restauración de prueba recuperó 19 usuarios y 31 tablas; la restauración definitiva volvió a confirmar los 19 usuarios. Redis recuperó 1144 claves activas en la verificación inicial. Cifras históricas, no invariantes. El propietario confirmó que la aplicación funciona, incluyendo descarga y descifrado del catálogo, archivos e inicio de sesión con recuperación de datos. No fue necesario actualizar la APK para migrar.

## Recursos aplicados en producción

| Servicio | Anterior | Nuevo máximo runtime |
|---|---:|---:|
| decoder-worker | 768 MiB | 4 GiB, 4 vCPU, cpu_shares 2048 |
| web | 1 GiB | 2 GiB |
| shop-db | 384 MiB | 1 GiB |
| redis | 96 MiB | 512 MiB |
| key-attestation | 384 MiB | 512 MiB |
| apk-qa | 320 MiB | retirado de producción |
| apk-tools | 1152 MiB efectivos | 1152 MiB observados; destino pendiente |

Se aplicaron mediante docker update sin recrear los contenedores. Los cinco servicios principales tienen memswap_limit igual a mem_limit; host sin swap en la última inspección. Los máximos suman 8 GiB, o 9.125 GiB incluyendo APK Tools. No son reservas. Conservar margen real para Linux, Nginx, cachés y picos. Se confirmó NanoCpus=4000000000. El usuario observó descifrados más rápidos; no se realizó benchmark controlado.

APK QA es un laboratorio que debe estar en otra VPS; no habilitarlo por defecto en producción. APK Tools seguía activo en el último inventario; verificar si soporta funciones comerciales independientes antes de retirarlo. No se ordenó eliminar imágenes ni volúmenes.

## Configuración persistente local

En la VPS se creó `/etc/spdecode/compose.resources.yaml`, modo 0600, fuera del checkout:

```yaml
services:
  web:
    mem_limit: 2g
    memswap_limit: 2g
  decoder-worker:
    mem_limit: 4g
    memswap_limit: 4g
    cpus: 4.0
    cpu_shares: 2048
  shop-db:
    mem_limit: 1g
    memswap_limit: 1g
  redis:
    mem_limit: 512m
    memswap_limit: 512m
  key-attestation:
    mem_limit: 512m
    memswap_limit: 512m
```

Se indicó modificar la función compose() del CLI instalado `/usr/local/bin/spdecode`, añadiendo `-f /etc/spdecode/compose.resources.yaml` después del Compose base. El propietario reportó que terminó el procedimiento; no se realizó nueva inspección independiente del CLI. El procedimiento guarda respaldo, valida sintaxis y configuración y no reinicia los servicios. Una actualización que reemplace el CLI podría perder la modificación local.

Validación sin imprimir secretos:

```bash
docker compose -p spdecode \
  --env-file /etc/spdecode/cloud.env \
  -f /opt/spdecode/repo/cloud/compose.yaml \
  -f /etc/spdecode/compose.resources.yaml \
  --profile commerce --profile hardware-security config --quiet
docker inspect spdecode-decoder-worker-1 \
  --format 'Memory={{.HostConfig.Memory}} NanoCPUs={{.HostConfig.NanoCpus}}'
docker stats --no-stream
spdecode status
```

## Contrato para instalador y actualizador (implementación en código pendiente)

- Centralizar argumentos Compose; aplicar el override local validado cuando exista en instalación, actualización, rollback, scripts y servicios que lo requieran. Si no existe, conservar compatibilidad con el Compose base.
- Ofrecer perfil de producción de 12 GB/6 vCPU y perfil ligero para VPS pequeñas. Comprobar RAM realmente utilizable y CPU; no imponer recursos superiores a la capacidad. Crear override de forma atómica con permisos seguros; no sobrescribir preferencias existentes del operador.
- Mantener /etc/spdecode/cloud.env, hpke.env, signing.env, claves, certificados, datos persistentes, proyecto Compose y configuración Nginx. No incluir secretos en Git ni imprimirlos. Respaldar CLI y validar antes de recrear.
- No reactivar automáticamente perfiles apk-qa ni apk-qa-tools; activación explícita de laboratorio. Verificar los flujos comerciales y las dependencias antes de retirar APK Tools.
- Comprobar salud y rollback; nunca ejecutar docker compose down -v en producción. No reiniciar Redis innecesariamente: configuración original temporal, sin AOF ni guardado periódico. El aumento de límite Docker no incrementa por sí solo maxmemory ni tmpfs.
- Conservar HPKE V2, atestación, autenticación, firma y controles de seguridad; no regenerar claves durante una optimización.

## Tiempos de descifrado y concurrencia (pendientes)

| Capa | Vigente observado | Objetivo candidato |
|---|---|---|
| Python archivos/textos | TIMEOUT_SECONDS=20 | archivos 300 s, textos 120 s |
| Python catálogo | CATALOG_TIMEOUT_SECONDS=120 | complejos 900 s |
| Gateway a worker | 25 s normal, 50 s export compatible, 135 s catálogo/server-vpn | por operación con margen; catálogo 930 s |
| Nginx V2 | proxy_read_timeout 155 s | 960 s si se valida flujo síncrono largo |
| Android C++ | conexión 10 s, estándar lectura 25 s, op 5: 55 s, op 10/19/20: 60 s, op 9/12: 165 s | coordinar por operación o usar trabajos asíncronos |
| Concurrencia worker | 4 trabajos activos, 2 pesados | hasta 10 activos, 4 pesados, sujeto a pruebas |
| Proveedores externos | deadlines independientes de 10–30 s | revisar por proveedor, no aumentar indiscriminadamente |

Referencias:
- `cloud/workers/python/engine.py`: TIMEOUT_SECONDS, CATALOG_TIMEOUT_SECONDS, _child_limits, validación de timeout y limpieza subprocess.
- `cloud/workers/python/server.py`: ACTIVE_JOBS y HEAVY_JOBS, espera pesada 6 s, socket 15 s.
- `cloud/web/lib/c3-gateway.mjs`: fetchWorker, AbortSignal.timeout, límites de respuesta.
- `cloud/web/lib/c35-provider.mjs` y `cloud/web/lib/server-vpn-provider.mjs`: deadlines y seguridad de red.
- `android/app/src/main/cpp/spdecode_transport.cpp`: límites de transporte C++/JNI.
- Nginx: location exacta /api/v2/transport del dominio API.

Separar plazos de CPU, reloj, cola, inactividad y proveedor. Revisar límites por proceso (RSS, CPU, PID, tamaños de entrada/salida), cancelar y limpiar subprocess, mantener cuotas y límites de seguridad. Medir antes de ampliar concurrencia; preservar capacidad para trabajos rápidos. Preferir trabajos asíncronos autenticados para tareas prolongadas, con identificadores opacos, autorización de propietario, expiración, progreso, cancelación, idempotencia, límites de cola y compatibilidad con clientes existentes. Si se mantiene el flujo síncrono, coordinar Android, Nginx, gateway y worker para evitar desconexiones prematuras. No ampliar tiempos de autenticación/atestación arbitrariamente ni registrar secretos. No anunciar 15 minutos ni 10 trabajos como funcionalidad disponible hasta superar pruebas.

## Pendientes operativos y aceptación

1. Implementar override en fuente del instalador y actualizador; probar instalación limpia, upgrade y rollback.
2. Confirmar destino de APK Tools y mantener QA aislado.
3. Implementar y validar tiempos de descifrado y concurrencia con cargas mixtas; operaciones rápidas deben retornar inmediatamente, sin OOM ni pérdida de controles.
4. Revisar persistencia Redis, maxmemory, almacenamiento y backups; ajustar PostgreSQL tras medir.
5. Verificar tareas cron/systemd propias de SP-DECODE, Dynamic DNS (impedir que la VPS antigua anuncie IP anterior), renovación SSL y copias automatizadas.
6. Verificar que límites sobrevivan recreación/actualización y que cuentas, catálogo, archivos, notificaciones y API continúen operativos.
7. Conservar servidor anterior como contingencia mientras se valida; nunca dos escritores simultáneos. Rollback tras nuevas escrituras requiere reconciliación/sincronización inversa.

Este documento registra lo realizado y los requisitos futuros; no modifica por sí mismo el instalador, actualizador, motor, Android ni la VPS.
