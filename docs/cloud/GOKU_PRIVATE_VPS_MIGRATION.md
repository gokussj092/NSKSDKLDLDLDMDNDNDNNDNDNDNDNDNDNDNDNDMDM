# SP-DECODE VPS: traslado seguro al repositorio privado Goku

## Alcance
Esta guía se aplica únicamente a la instalación Cloud C8 que usa
`/opt/spdecode/repo`, `/etc/spdecode/install.conf`,
`/etc/spdecode/cloud.env` y `/usr/local/bin/spdecode`.
No volver a ejecutar el instalador inicial, `panel reset-admin`,
`docker compose down -v`, ni regenerar certificados o secretos.

Rama de migración (mantiene los cambios de aplicación 1.1.21):
`fix/goku-private-vps-migration`.
Nuevo remoto privado: `git@github-spdecode-goku:gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM.git`.
La CLI permite también la URL anterior durante el periodo de recuperación.
La aplicación Android 1.1.21 no necesita recompilarse solo por cambiar el remoto
del servidor.

## 1. Inspección segura (sin cambiar servicios)

```bash
sudo -i
test -d /opt/spdecode/repo/.git && echo "CLOUD_REPO_PRESENTE"
test -f /etc/spdecode/install.conf && echo "INSTALL_CONF_PRESENTE"
test -f /etc/spdecode/cloud.env && echo "CLOUD_ENV_PRESENTE"
git -C /opt/spdecode/repo remote -v
git -C /opt/spdecode/repo status --short
git -C /opt/spdecode/repo rev-parse HEAD
command -v spdecode
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

Si no aparecen las tres rutas de Cloud, DETENERSE y localizar la instalación.
Nunca mostrar `/etc/spdecode/cloud.env` ni contraseñas en el chat.

## 2. Autenticación privada de solo lectura

Crear una clave dedicada para el VPS (sin reemplazar claves existentes):

```bash
install -d -m 700 /root/.ssh
test ! -e /root/.ssh/spdecode_goku_deploy
ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/spdecode_goku_deploy -C spdecode-vps-readonly
cat /root/.ssh/spdecode_goku_deploy.pub
```

En GitHub Goku > repositorio > Settings > Deploy keys > Add deploy key.
Pegar SOLO la clave .pub. Mantener desmarcado Allow write access.
El propietario no necesita convertir el repositorio en público.

Antes de aceptar la clave de host de GitHub, verificar la huella Ed25519
`SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU` en la
documentación oficial de GitHub. No aceptar una huella diferente.

Configurar alias exclusivo de esta app, sin afectar otras claves SSH:

```sshconfig
Host github-spdecode-goku
    HostName github.com
    User git
    IdentityFile /root/.ssh/spdecode_goku_deploy
    IdentitiesOnly yes
    HostKeyAlias github.com
    StrictHostKeyChecking yes
```

Guardar ese bloque una sola vez en `/root/.ssh/config` (permisos 600).
Registrar la clave de host verificada en `/root/.ssh/known_hosts`.

Probar ANTES de cambiar el remoto:

```bash
git ls-remote 'git@github-spdecode-goku:gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM.git' "refs/heads/fix/goku-private-vps-migration"
```

Debe devolver un commit. Si falla la autenticación o la rama no existe,
no cambiar el VPS.

## 3. Respaldar y cambiar de origen, sin desplegar aún

```bash
spdecode backup
install -d -m 700 /root/spdecode-migration-backup
cp -p /etc/spdecode/install.conf /root/spdecode-migration-backup/install.conf.before
cp -p /usr/local/bin/spdecode /root/spdecode-migration-backup/spdecode.before
git -C /opt/spdecode/repo remote -v > /root/spdecode-migration-backup/remote.before
git -C /opt/spdecode/repo rev-parse HEAD > /root/spdecode-migration-backup/commit.before
git -C /opt/spdecode/repo status --porcelain
```

El último comando debe estar vacío. Revisar el respaldo antes de continuar.
Cambiar únicamente el Git remoto:

```bash
git -C /opt/spdecode/repo remote set-url origin 'git@github-spdecode-goku:gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM.git'
git -C /opt/spdecode/repo fetch --no-tags origin 'fix/goku-private-vps-migration'
git -C /opt/spdecode/repo show FETCH_HEAD:cloud/infra/vps/spdecodectl > /root/spdecode-migration-backup/spdecode.goku
bash -n /root/spdecode-migration-backup/spdecode.goku
```

**NO ejecutar aún `spdecode update all`**; la CLI instalada comprueba
`SPDECODE_REPO_URL`, que todavía contiene el origen antiguo.

Solo después de revisar el nuevo script:
1. Instalar la CLI nueva desde `spdecode.goku`, conservando la anterior.
2. Editar de forma atómica exclusivamente `SPDECODE_REPO_URL` y
   `SPDECODE_REF` en `/etc/spdecode/install.conf` preservando modo 0600
   y las demás variables.
3. Validar `spdecode status`, `nginx -t` y el remoto privado.
4. Con respaldos off-VPS y ventana de mantenimiento,
   ejecutar `spdecode update all fix/goku-private-vps-migration`.
5. Comprobar web, worker, HTTPS, panel y configuración del catálogo para
   cliente Android 1.1.21 antes de habilitar la función nueva.

El actualizador resetea el checkout al commit remoto y reconstruye servicios.
Su rollback automático cubre fallos de despliegue, no todas las migraciones de
datos ni el comportamiento funcional. Guardar también copias cifradas externas
de credenciales y datos persistentes según la arquitectura real.

Si falla el acceso SSH ANTES del despliegue, restaurar el remoto desde el
valor guardado; no usar `git reset --hard` manualmente. Si falla DESPUÉS,
evaluar `spdecode rollback` y restaurar la CLI compatible antes de modificar
más valores. No abrir el repositorio ni publicar claves privadas.
