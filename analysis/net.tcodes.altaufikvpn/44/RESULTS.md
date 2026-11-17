# ALTAUFIK VPN 5.01 — RESULTS

Fecha de verificación: 2026-11-17. Entorno: Python 3.12.3 del sistema
y venv con pycryptodome 4.4.0
(`~/workspace/http-custom-update/venv/bin/python`).

## Estado por vía

- **catalog**: VERIFIED — VIP en vivo v9.5 abre completo; gratis en
  vivo muerto (fallo honesto); integrados gratis v9.6 y VIP v8.3 abren.
- **files**: NOT_APPLICABLE — sin formato propio de archivo.
- **text**: NOT_APPLICABLE — sin esquema URI propio.
- **export**: PENDING — sin compartir por código, registro de
  dispositivo ni créditos en 5.01.

## Catálogo en vivo

| Fuente | Version | Servers | Tweaks | Tweaks con Payload |
| --- | --- | --- | --- | --- |
| Remoto VIP (`--vip --url`) | **9.5** | **7** | **1458** | **1343** |
| Remoto gratis (`--url`) | — | — | — | **MUERTO: HTTP 200, 2 bytes (`ff`)** |
| `assets/defconf` (gratis integrado) | 9.6 | 4 | 1486 | 1386 |
| `assets/vip_defconf` (VIP integrado) | 8.3 | 7 | 1568 | 1447 |

Re-corrida en vivo 2026-11-17: `--vip --url` produce salida
**byte-idéntica** a `live.json` (SHA-256
`028d5f18f911def005fdc26a190edb9832386d44381a6acafc3bde072ea7f454`).
`--url` (gratis) falla con `FORMAT_ERROR`, exit 1, como en la
primera medición (`live_probe.json`: gratis HTTP 200, 2 bytes,
SHA-256 `05a9bf223fedf80a9d0da5f73f5c191a665bf4a0a4a3e608f2f9e7d5ff23959c`,
`Last-Modified: Fri, 06 Oct 2023`; VIP HTTP 200, 670572 B, SHA-256
`c4fa25ab0accc3088f0a84d5e11de33eab75ef11634ba6b0d061ab767aa962f4`,
`Last-Modified: Thu, 19 Mar 2026 14:39:02 GMT`).

## Self-test del script operativo

`Altaufik_VPN.py --self-test` (venv): `{"synthetic_envelope": true,
"plain_json_passthrough": true, "dead_free_body_rejected": true,
"ok": true}`, exit 0. `py_compile` OK.

## Tests del expediente

`python -m unittest discover -s tests -v` — ver salida en la entrega.
Vectores SINTÉTICOS: sobre Salted__ sintético con la contraseña de
formato (el mismo vector del `--self-test`), rechazo del cuerpo muerto
(`ff`), rechazo de sobre truncado, rechazo de documento sin listas,
passthrough de JSON plano y estructura del fixture sintético. Un
fixture sintético demuestra la lógica implementada, NO prueba
compatibilidad con una versión real ni conectividad remota; eso lo
prueba la re-corrida en vivo de arriba.
