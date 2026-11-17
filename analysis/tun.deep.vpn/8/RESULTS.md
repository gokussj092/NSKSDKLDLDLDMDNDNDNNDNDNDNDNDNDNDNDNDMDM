# DeepTune-VPN v8 — RESULTS

Fecha de verificación: 2026-11-17. Entorno: Python 3.12.3, venv de
verificación con `argon2-cffi` 25.1.0, `cryptography` 50.0.2,
`requests` 2.34.2, `pycryptodome` 4.5.0.

## Re-corrida en vivo (2026-11-17)

- Comando: `deeptune_vpn_catalog.py -o catalogo.json`
- Resultado: catálogo **v3.12, 6 servidores, 102 redes**.
  Duración total **17,6 s** (dentro del tope de 120 s del catálogo).
- Comparación con la muestra entregada (`work/live.json`, v3.11,
  101 redes): **NO byte-idéntica (deriva viva legítima)** — la única
  diferencia es `Version` 3.11 → 3.12 y UNA red nueva (`🇸🇦 KSA |
  Mobily FR 10% WORK ✈`); los 6 servidores son idénticos campo a
  campo y las 101 redes anteriores no cambiaron.
- El resultado JSON NO contiene la ruta ni el nombre del archivo de
  descarga (verificado: sin la ruta del endpoint ni el nombre del
  archivo remoto en el JSON; las únicas URLs son datos del catálogo).

## Asset empaquetado

- Comando: `deeptune_vpn.py work/bundled.json`
- Resultado: **v1.01, 9 servidores, 111 redes** en 5,1 s.

## Auditoría de campos (sobre v3.12)

- Campos de servidor que NO abren con ninguna contraseña: **12**
  (`SlowDNSHost` ×3, `SlowDNSKey` ×6, `V2rayUUID` ×3). Incluye los 9
  ya reportados en los 3 servidores OVPN/SSH + 3 `SlowDNSKey` en los
  otros 3 servidores (otro cifrado compartido).
- Valores que SÍ descifran pero el script no intenta: **48**
  (`ServerIPHost`/`UDP_obfs`/`UDP_user`/`H2pass` ×6 servidores = 24;
  `BugDNS` ×24 redes, todos a `8.8.8.8`). Ejemplo: `ServerIPHost`
  de `Global Server Online--01` → `sm.mtmtun.com`.
- `py_compile` de ambos scripts: OK.

## Tests del expediente

- `tests/test_method.py`: sobre Argon2id+AES-GCM genérico con clave
  de prueba sintética (round-trip, sensibilidad a salt, rechazo de
  tag inválido) + forma del fixture sintético. Sin red, sin claves
  reales.

## Negativos / pendientes

- 12 valores de campo sin abrir (clave no recuperada del APK).
- ~~48 valores no intentados por las listas de campos~~ — **RESUELTO por el coordinador 2026-11-17**: listas ampliadas (`ServerIPHost`, `UDP_obfs`, `UDP_user`, `H2pass`, `BugDNS`) tras verificar en vivo que los 48 descifran con las contraseñas existentes; re-corrida v3.12 confirmada. La rama del bridge reporta solo los 12 reales en `decryptionStatus` (regla precisa por campo, ver REPORT.md).
- `cryptography` NO está en el `requirements.txt` raíz del repo
  (verificado con venv limpio: `ModuleNotFoundError`); sin ella el
  worker no puede importar los scripts.
- Sin esquema de enlace propio ni extensión de archivo propia.
