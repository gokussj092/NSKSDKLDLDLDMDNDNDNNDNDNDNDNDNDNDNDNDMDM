# Resultados — HTTP Custom 8.1.5 (build 942), 3 archivos .hc

- Fecha: 2026-11-23/24 (Tijuana). Decodificador probado:
  `decoders/Python/HTTPCUSTOM.py` (repo, sin modificar).
- Método de verificación del sobre: `codec.py::open_envelope` (HCX4-v4).
- Sonda KDF: `tools/probe_n19.py` (control 934 validado).

## Matriz por archivo

| Archivo | Schema / schedule | Build | Protección | Sobre exterior HCX4-v4 | Decodificador actual | Estado |
|---|---|---|---|---|---|---|
| test_bloqueo_normal_con_contrase_a_0_m46a.hc (4,981 B, SHA-256 `bf837b78…`) | b=14 / n19 | 942 | h=1, contraseña Argon2id (a1/l=2/m=67108864) | OK | FAIL — `UNSUPPORTED_SCHEMA` | PENDING — falta contraseña + KDF n19 desconocida |
| test_bloqueo_normal_1_aflj.hc (4,935 B, SHA-256 `8a69d0fb…`) | b=14 / n19 | 942 | h=0, sin contraseña | OK | FAIL — `UNSUPPORTED_SCHEMA` | PENDING — KDF n19 desconocida (sin contraseña necesaria) |
| test_open_2_7xqg.hc (4,529 B, SHA-256 `c180dce9…`) | b=14 / n19 | 942 | h=0, sin contraseña | OK | FAIL — `UNSUPPORTED_SCHEMA` | PENDING — KDF n19 desconocida; sonda 0/35 |

## Controles (misma sesión, misma CLI)

| Archivo | Resultado |
|---|---|
| `drive/Test Oppen.hc` (934, b=12/n15, h=0) | PASS (exit 0) — el decodificador funciona sobre 934 |
| `drive/Test password2.hc` (934, b=12/n15, h=1) | `PASSWORD_REQUIRED` (sin contraseña dada) |
| `drive/Test bloqueo password y hwid.hc` (934, b=12/n16) | `UNSUPPORTED_SCHEMA` (n16 sigue cerrado) |
| Sonda `probe_n19.py --control` (Test Oppen.hc) | 2/35 — abre con la construcción n15 documentada (harness validado) |
| Sonda `probe_n19.py` (test_open_2_7xqg.hc) | **0/35** — ninguna construcción candidata autentica la sección `i` |

## Veredicto

- **0/3 archivos abren.** El formato nuevo es b=14/n19; el sobre exterior
  no cambió (HCX4-v4 autentica); la KDF interior n19 no se recuperó por
  vía estática.
- **No hay decodificador actualizado que abra estos archivos** (propuesto,
  no implementado): sin la KDF interior, cualquier lector n19 sería
  inventado. No se modificó `HTTPCUSTOM.py` ni se hizo push.
- Pendiente: (1) KDF interior n19 — vía realista: script lector para
  8.1.5 (precedente n15) o recuperación de prestates del motor nativo
  8.1.5; (2) contraseña del archivo 1 (no proporcionada por Pedro).

## Verificación de la fusión — 2026-11-26 (staging, sin commit ni push)

- `test_open_2_7xqg.hc`: **PASS** — abre, `8.1.5 (942)`, 2 perfiles, banner
  `{"version": 1, "style": "custom", "content": "annsksk"}`.
- `test_bloqueo_normal_1_aflj.hc`: **PASS** — abre, `8.1.5 (942)`, 2
  perfiles, mismo banner.
- `test_bloqueo_normal_con_contrase_a_0_m46a.hc`: `PASSWORD_REQUIRED` sin
  credencial; `AUTH_FAILED` con contraseña incorrecta. Apertura con la
  contraseña correcta PENDIENTE (no proporcionada).
- Controles: 934 real (`drive/Test Oppen.hc`) abre con salida byte-idéntica
  al codec sin modificar; suite HC 23 passed / 82 subtests passed / 5 failed
  preexistentes (`C8 engine unavailable`), idéntico en worktree intacto y
  árbol fusionado; negativos n16 `UNSUPPORTED_SCHEMA`, Gjost
  `HWID_REQUIRED`, 884 sin cambios (`Unsupported schema b=8`).
- Textos `hccloud://`: la referencia se reescribe a https y los bytes llegan
  sin reescribir al mismo codec; tests JS 14 pass / 3 fail preexistentes
  (`INVALID_ORIGINAL_ICON`, ajenos a la fusión).
- Veredicto actualizado: **2/3 archivos abren; KDF n19 recuperada e
  integrada en staging**. Detalle: `tools/VERIFICATION_2026_11_26.md`.
