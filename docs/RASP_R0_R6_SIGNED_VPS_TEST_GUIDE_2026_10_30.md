# SP-DECODE R0–R6 — Android release firmado y VPS de pruebas

Este ZIP de GitHub Actions incluye APK/AAB release R8, con versionName 1.1.24 y versionCode 38 (solo en runner CI), usando el certificado de SUBIDA que ya está en GitHub Secrets. No es una APK re-firmada por Google Play. No se fusiona main, no hay despliegue automático.

## Archivos y restricciones

APK: SP-DECODE-1.1.24-b38-R0-R6-SIGNED-RELEASE-TEST.apk.
AAB: SP-DECODE-1.1.24-b38-R0-R6-SIGNED-RELEASE-TEST.aab.
Hashes: SHA256SUMS.txt; metadata: BUILD_INFO.txt y RELEASE-TEST-INFO.txt.

La APK firmada con upload certificate puede ser rechazada por Play Integrity o no actualizar directamente una instalación distribuida por Google Play, que utiliza otro certificado App Signing. Para Play Integrity real, subir el AAB a pista interna de Google Play y descargarlo desde allí. No desinstalar la app actual ni borrar identidades NPVS para forzar una instalación.

## 1. Seguridad previa (SSH, usuario con sudo)

    sudo spdecode status
    sudo spdecode backup
    sudo test -s /etc/spdecode/cloud.env
    sudo test -s /etc/spdecode/keys/v2-hpke-keyring.json
    sudo test "$(sudo stat -c '%a' /etc/spdecode/cloud.env)" = 600
    sudo test "$(sudo stat -c '%a' /etc/spdecode/keys/v2-hpke-keyring.json)" = 600
    sudo grep -Eq '^CLOUD_V2_HPKE_ENABLED=true$' /etc/spdecode/cloud.env
    sudo grep -Eq '^CLOUD_V2_HPKE_KEYRING=.+' /etc/spdecode/cloud.env
    git -C /opt/spdecode/repo status --short
    git -C /opt/spdecode/repo rev-parse HEAD

Si falla alguna comprobación, detener el despliegue. No imprimir ni compartir claves, variables completas o Docker Compose config. Mantener backup cifrado fuera del VPS del env, keyring HPKE, config, datos y estados de contenedores; spdecode backup no lo cubre todo.

## 2. Recomendación: primero VPS de staging

Probar en un entorno aislado, con claves sintéticas que no son de producción, sin puertos públicos ni tráfico real. El CI solo simula Compose parcial, no un rollback total del VPS.

## 3. Actualización del VPS actual (operación REAL, ejecutarla solo tras preflight)

    sudo spdecode update all feat/post-native-security
    sudo spdecode status
    git -C /opt/spdecode/repo rev-parse HEAD
    curl -fsS --max-time 15 https://api.spdecode.xyz/api/health/live

El check /health/live NO certifica que HPKE descifre correctamente. Verificar manualmente una solicitud protegida con fixture no sensible. La rama arranca con CLOUD_RASP_MODE=observe (no enforce) para no afectar a clientes actuales. No modificar CLOUD_V2_HPKE_ONLY ni rotar el keyring para hacer pruebas.

Rollback de código ante fallo:

    sudo spdecode rollback
    sudo spdecode status

Si el cloud.env o el keyring se perdió, rollback de Git no los restaura. Recuperar respaldo seguro siguiendo el runbook de HPKE.

## 4. Matriz de cierre R0-R6

- [ ] Comprobar APK release firmada, paquete, versionCode 38, ABI, R8 y hashes.
- [ ] Subir AAB a pista interna de Play; comprobar App Signing y Play Integrity real.
- [ ] Prueba HPKE cifrada de ida/vuelta contra worker; verificar respuesta autenticada.
- [ ] NPVS v1/v5/v6 con fixtures de contraseña, destinatario y errores tipados.
- [ ] Anti-tamper con APK resignada, debugger/hook de laboratorio y recuperación segura.
- [ ] ADB, Termux, Shizuku, VPN, accesibilidad y perfiles de trabajo sin falsos positivos.
- [ ] Dos fabricantes, distintos SDK, p50/p95, RAM/CPU/batería.
- [ ] Backup, recreate, update y rollback completos del VPS staging sin perder KID.
- [ ] Aprobar políticas RASP y eventual cambio a enforce por etapas.

Referencias: docs/HPKE_VPS_DEPLOYMENT_SAFETY_RUNBOOK_2026_10_30.md y docs/RASP_R0_R6_IMPLEMENTATION_2026_10_30.md.
