# Comprobación breve — Focus VPN Cloud 5.0

2026-10-22, build 59. Fuente y formato recuperados de `ConfigUtil`, sus clases
internas, `ConfigUpdate`, `AESCrypt`, `FocusActivity`, `SSLdirecto` y `V2Config`.

| Documento | Version | Servidores | Campos cifrados no vacíos | JSON completo frente al JDK |
| --- | --- | --- | --- | --- |
| APK flags/fc.png | 1 | 1 | 0 | Igual |
| Descarga HTTPS real | 1081 | 142 | 590 | Igual |

La fuente remota devolvió 200 y **1015056 bytes**, SHA-256
`a20203e8ae622d6fbf8348f13039898daf4c2478061354c86cd767a198cc6644`.
La CLI `--download` y el worker aislado devuelven el documento remoto completo
igual al oracle, `isPartial:false`. Comparación con Java `AES/CBC/PKCS5Padding`
y `RC4`, independiente del lector Python. No es ejecución completa de Android.

Solo se ejecutan comprobaciones dirigidas por petición del usuario:

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_focus_vpn_cloud -v
cd cloud/web
node --test tests/focus-vpn-cloud-remote.test.mjs tests/server-vpn-catalog.test.mjs
```

**3 pruebas Python y 17 web aprobadas**. Cubren JSON sintético íntegro producido
por JDK, proceso aislado, CLI por stdin fuera del repositorio, entrada inválida,
límites, fuente fija, DNS/IP públicos, TLS, rechazo de redirecciones, icono exacto,
versión y disponibilidad de fichas. `git diff --check` correcto.

No se ejecutan suites completas, Android, sesiones VPN, gateway autenticado hacia
la VPS o despliegue. El transporte externo Node se prueba de forma controlada;
HTTPS real y descarga CLI se comprobaron por Python. No se presupone CI remota.
Los vectores públicos son sintéticos; los documentos reales permanecen fuera de Git.
