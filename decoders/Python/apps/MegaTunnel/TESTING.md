# Comprobación breve — MegaTunnel 1.17.1

Validación 2026-10-22, build 17. Inspeccionados `G2`, `C0169Cf`, `XW.m`,
`AbstractC2562yx.a`, `PW.a/b`, `Z7` y selección/actualización de `MainActivity`.

| Fuente | Versión | Servidores | Ajustes | Campos procesados | No vacíos comparados |
| --- | --- | --- | --- | --- | --- |
| HTTPS real | 0.2 | 10 | 124 | 297 | 210 |

Respuesta **200**, **64713 bytes**, SHA-256
`b89a4a83fed75f2316db70b8391a62367e008fbaa557747a4228f01c3ac218bf`.
El JSON completo, incluidos todos los campos desconocidos y vacíos, coincide con
un oracle JDK independiente de AES-GCM y Base64/XOR. La descarga Python, CLI real
`--download` desde fuera del repo y proceso aislado coinciden con el mismo
documento íntegro, `isPartial:false`. No se usa una salida sintética para afirmar
que funciona la descarga real. Los vectores públicos son exclusivamente sintéticos.

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_megatunnel -v
cd cloud/web
node --test tests/megatunnel-remote.test.mjs tests/server-vpn-catalog.test.mjs
```

**3 pruebas Python y 20 web aprobadas**. Cubren los 13 campos del esquema,
ambas listas, registros con campos ausentes, metadatos/tipos/vacíos conservados,
worker, stdin fuera del repo, tag alterado, campos y secciones inválidos, claves
JSON duplicadas, truncamiento, límites, fuente fija, DNS/IP/TLS, rechazo de
redirecciones, icono exacto y disponibilidad. `git diff --check` correcto.

Según la petición del usuario no se ejecutan suites completas. Transporte Node
controlado; HTTPS externo real por Python. Sin sesión VPN, Android, gateway
hacia VPS desplegada, despliegue o CI remota acreditados. No se certifica el
importador `.meg` ni un catálogo separado de usuarios. Sin APK, catálogos reales,
perfiles privados o credenciales descodificadas en Git/CI.
