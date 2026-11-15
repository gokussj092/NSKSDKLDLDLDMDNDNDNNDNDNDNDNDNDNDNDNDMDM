# Persistencia de recursos de la VPS — 2026-11-15

Rama: `patch/20-apps`. Corrección sobre `6d92b62d42749796aeff5955ab60321d4ef35060`.

## Estado comprobado mediante la salida aportada por el propietario

| Contenedor | Límite RAM | CPU | CPU shares |
|---|---:|---:|---:|
| decoder-worker | 4 GiB (4294967296 B) | 4 | 2048 |
| web | 2 GiB (2147483648 B) | 1 | valor por defecto |
| shop-db | 1 GiB (1073741824 B) | sin límite explícito | valor por defecto |
| redis | 512 MiB (536870912 B) | sin límite explícito | valor por defecto |
| key-attestation | 512 MiB (536870912 B) | 1 | valor por defecto |

El archivo `/etc/spdecode/compose.resources.yaml` existe. El CLI instalado tras
la actualización anterior no lo incluía. Los límites efectivos se conservaron
en esa actualización, pero no había persistencia garantizada para recreaciones
posteriores. Esta sesión no accede directamente al Docker de producción.

## Corrección

- `spdecodectl` carga el archivo local si existe, después del Compose base. Se
  aplica a las operaciones que pasan por su función Compose: actualización,
  reinicio y rollback, además de los comandos de gestión del servicio.
- La función del CLI es autocontenida: sigue usando el mismo archivo externo
  aunque un update/rollback cambie el checkout a una revisión anterior.
- Instalador, recuperación TLS y recuperación de contenedores también incluyen
  el archivo existente. No crean límites grandes por defecto en VPS pequeñas.
- Los comandos Python de proveedores, QA y reinicio del panel utilizan el mismo
  archivo protegido al recrear web, mediante `spdecode_compose.py`.
- Un archivo ausente conserva el funcionamiento anterior con el Compose base.
  Una ruta existente no válida se rechaza; no se ignora para usar límites bajos.
- El archivo se lee, no se sobrescribe. No se cambian sus valores, los secretos,
  perfiles, volúmenes ni la concurrencia/tiempos del motor.
- `spdecode backup` incluye una copia `resources-<fecha>.yaml` con modo 0600.

## Primera actualización desde el CLI anterior

No ejecutar la primera recreación usando el CLI viejo que ignora el archivo.
Desde la VPS, este bloque descarga y ejecuta temporalmente el CLI corregido.
Ese CLI respeta el override desde el comienzo, respalda la configuración,
actualiza al commit descargado e instala el nuevo CLI al terminar correctamente:

```bash
sudo bash -euo pipefail <<'SH'
umask 077
repo=/opt/spdecode/repo
git -C "$repo" fetch --no-tags origin patch/20-apps
revision=$(git -C "$repo" rev-parse 'FETCH_HEAD^{commit}')
staged=$(mktemp /root/spdecode-resources-fix.XXXXXX)
trap 'rm -f "$staged"' EXIT
git -C "$repo" show "$revision:cloud/infra/vps/spdecodectl" > "$staged"
bash -n "$staged"
bash "$staged" backup
bash "$staged" update all "$revision"
SH
```

Las actualizaciones posteriores que usen este CLI pueden volver a:

```bash
sudo spdecode update all patch/20-apps
```

Una vuelta permanente a una revisión anterior a la corrección puede reinstalar
un CLI antiguo; ese caso necesita de nuevo el procedimiento de arranque anterior.
El rollback ejecutado por el CLI corregido mantiene el override durante esa
operación. No se promete que herramientas antiguas conozcan esta funcionalidad.

## Comprobación en la VPS

```bash
sudo docker inspect \
  spdecode-decoder-worker-1 spdecode-web-1 spdecode-shop-db-1 \
  spdecode-redis-1 spdecode-key-attestation-1 \
  --format '{{.Name}} RAM={{.HostConfig.Memory}} CPU={{.HostConfig.NanoCpus}} CPUshares={{.HostConfig.CpuShares}}'
sudo spdecode status
```

La mera existencia del YAML no basta: confirmar los límites efectivos después
de la recreación. No mostrar `cloud.env` ni el resultado completo de `compose
config`; para validar la configuración completa sin revelar valores, usar
`config --quiet`.

## Validación de código

- 71 pruebas de `cloud/infra/vps/tests`: todas correctas, incluidas 7 regresiones
  nuevas que ejecutan los constructores de comandos reales de los 7 puntos de
  entrada (4 shell y 3 Python) sin contactar Docker.
- Comprueban archivo presente/ausente, orden base → override, rutas con espacios,
  rechazo de directorios/enlaces rotos, conservación de contenido/permisos,
  backup 0600, cambio de checkout para update/rollback y ausencia de secretos.
- 7 pruebas de guardas HPKE y 9 pruebas de CLI APK QA: correctas.
- Sintaxis Bash de instalador/recuperación/CLI: correcta.
- Sin recreación real de contenedores en este entorno; la aplicación en la VPS
  queda pendiente de que el propietario ejecute el bloque y confirme Docker.

La generación automática de perfiles según RAM/CPU y los nuevos presupuestos
de concurrencia/tiempos del documento de optimización siguen pendientes.
