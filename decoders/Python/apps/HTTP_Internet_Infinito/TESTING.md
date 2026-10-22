# Comprobación breve — HTTP Internet Infinito 1.3.9

Validación 2026-10-22, build 139. Inspeccionados updater `A2.a`, lectores
`p083u2.c/d/g/i`, recursos de campos y propiedades de `assets/LICENSE`.

| Fuente | Version | Registros | Campos procesados | No vacíos comparados con JDK |
| --- | --- | --- | --- | --- |
| HTTPS real | 1103 | 74 servidores | 789 | 586 |
| APK flags/config.png | 1 | 1 servidor | 11 | 8 |
| APK flags/usr.png | 1 | 1 usuario | 7 | 7 |

Los tres documentos JSON completos coinciden con una transcripción JDK
independiente de MD5/AES-CBC y rotación UTF-16; se conservan también los vacíos.
Respuesta remota **200**, **91584 bytes**, SHA-256
`f65fb3fc8b1e3b5b23e25fa58496aec1b7f42eca8b4155f4ba933a9fde3f3ff8`.
Descarga Python, CLI real `--download` desde fuera del repo y proceso aislado
coinciden íntegramente con `isPartial:false`. Las pruebas públicas contienen
únicamente vectores sintéticos producidos por el oracle Java.

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_http_internet_infinito -v
cd cloud/web
node --test tests/http-internet-infinito-remote.test.mjs tests/server-vpn-catalog.test.mjs
```

**3 pruebas Python y 19 web aprobadas**. Comprueban todos los campos del esquema,
servidores/usuarios, metadatos y vacíos, worker, stdin fuera del repo, registros
inválidos, claves duplicadas, entrada incompleta, límites, fuente HTTPS fija,
DNS/IP/TLS, rechazo de redirecciones, icono exacto y disponibilidad. Se admite
Base64 sin padding; el caso truncado elimina datos, no solo padding opcional.
`git diff --check` correcto.

Sin suites completas por petición del usuario. HTTPS externo Python real;
transporte Node controlado, sin afirmar descarga externa Node, CI remota,
despliegue VPS, ejecución Android o conexión VPN. No se certifica un catálogo
remoto de usuarios ni archivos de perfil exportados. No se publican APK ni datos
reales descifrados.
