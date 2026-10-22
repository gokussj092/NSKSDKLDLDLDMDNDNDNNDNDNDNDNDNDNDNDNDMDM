# Comprobación breve — FreedomVPN 1.0.29

Validación 2026-10-22, build 125. Inspeccionados `j8`, `Ri`, `Mi`, `CU`, `P5`,
`Cf`, `iv`, `V10`, lectores de rotación y updater `w0` del APK.

| Fuente | Version | Servidores | Campos cifrados comparados | JSON completo frente al JDK |
| --- | --- | --- | --- | --- |
| APK config/config.json | 1.0.0 | 1 | 8 | Igual |
| HTTPS real | 4.4.88 | 147 | 1176 | Igual |

Respuesta remota 200, **292761 bytes**, SHA-256
`9bb1f8f6c99935c2b591f4b93e01a8a7d7655bf56e0e89cdeca5c744e81856a7`.
La CLI real y el proceso aislado devuelven el mismo documento completo,
`isPartial:false`. El oracle JDK implementa independientemente la variante
XXTEA del APK, AES-ECB, símbolos/AES-CBC y rotación UTF-16; también produce los
vectores sintéticos públicos. No depende del lector Python.

Se ejecutan solo comprobaciones dirigidas, según petición del usuario:

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_freedomvpn -v
cd cloud/web
node --test tests/freedom-vpn-remote.test.mjs tests/server-vpn-catalog.test.mjs
```

**3 pruebas Python y 18 web aprobadas**. Cubren resultado íntegro, ocho campos
con claves distintas, metadatos/valores vacíos, worker, stdin fuera del repo,
entrada corrupta/límites, fuente fija, DNS/IP/TLS y rechazo de redirecciones,
icono original, disponibilidad y versión. `git diff --check` correcto.

La comparación de ServerPass acredita el dato almacenado compatible con P5;
no certifica la credencial dinámica que el cliente genera por hora/dispositivo.
No se ejecutaron suites completas, Android, gateway autenticado hacia VPS,
sesiones VPN ni despliegue. Transporte externo Node controlado; descargas
externas y CLI reales por Python. No se presupone CI remota. No hay datos
reales, APK o credenciales descodificadas en Git/CI.
