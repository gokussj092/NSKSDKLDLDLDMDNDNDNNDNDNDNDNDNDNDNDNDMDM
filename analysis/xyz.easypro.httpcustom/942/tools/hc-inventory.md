# Inventario estructural — HTTP Custom 8.1.5 (build 942), 3 archivos .hc

- Fecha: 2026-11-23 (Tijuana)
- Alcance: solo lectura y pruebas locales. No se modificó el repo ni se hizo push.
- Decodificador probado: `~/workspace/spdecode-patch/decoders/Python/HTTPCUSTOM.py` (CLI, sin contraseña ni HWID; no se dieron credenciales, no se adivinó ninguna).
- Método de sobre exterior: HCX4-v4 del codec del repo (`apps/HTTP_Custom/codec.py::open_envelope`,
  clave derivada de `native_fold` del sello v4, AAD `HCX4|xyz.easypro.httpcustom|1`).
  Corrección metodológica: el método exterior de `hc884_decode.py` (HKDF-v1 / clave V3)
  NO abre ni los archivos 934 ni estos 815 — solo servía para build 884 (b=8/n9).
  El sobre de 934 y 815 autentica con HCX4-v4.
- Regla aplicada: solo metadatos estructurales. No hay credenciales, contraseñas, HWIDs
  ni contenido descifrado en este documento. De la semilla `g` solo se registra
  longitud y prefijo del SHA-256, nunca el valor.

## Tabla resumen

| Archivo | Schema b / schedule e | Build n | h (protegido) | Secciones i / j | Sobre exterior HCX4-v4 | Decodificador actual |
|---|---|---|---|---|---|---|
| test_bloqueo_normal_con_contrase_a_0_m46a.hc | b=14 / n19 | 942 | 1 (contraseña Argon2id) | i + 2 | OK | FAIL — `HTTP Custom HCCFG: UNSUPPORTED_SCHEMA` (exit 1) |
| test_bloqueo_normal_1_aflj.hc | b=14 / n19 | 942 | 0 (sin contraseña) | i + 2 | OK | FAIL — `HTTP Custom HCCFG: UNSUPPORTED_SCHEMA` (exit 1) |
| test_open_2_7xqg.hc | b=14 / n19 | 942 | 0 (sin contraseña) | i + 2 | OK | FAIL — `HTTP Custom HCCFG: UNSUPPORTED_SCHEMA` (exit 1) |

## Detalle por archivo

### 1. test_bloqueo_normal_con_contrase_a_0_m46a.hc
- Tamaño: 4,981 B — SHA-256: `bf837b783b014328c5c0626e1d555430bb7afa133d0dc8f9df51c4b89fd74432`
- Sobre: `a=HCCFG`, `b=14`, `c=s1`, `d=h1`, `e=n19`, `f=["ssh","profiles"]`, `n=942`
- Semilla `g`: 32 bytes (hex 64) — SHA-256 prefijo `3f6f455f17131347` (solo prefijo, no el valor)
- Protección: `h=1`, `k=a1`, `l=2`, `m=67108864` (Argon2id, mismos parámetros que los n15 protegidos de 934)
- Sin cápsula `p`. Sin slots HWID `o`.
- Sección `i`: label len 1, nonce hex len 48, ct hex len 872. Sin sidecar.
- Secciones `j`: 2 secciones (label len 2, nonce hex len 48).
  - j[0]: ct hex len 1136, con sidecar `d` (nonce hex len 48, ct hex len 48).
  - j[1]: ct hex len 742, sin sidecar.
- Sobre exterior HCX4-v4: OK (autentica).
- Decodificador actual: FAIL, exit 1, stderr exacto:
  `Error al ejecutar el decodificador: HTTP Custom HCCFG: UNSUPPORTED_SCHEMA`
  Nota: el chequeo de schema ocurre antes que el de contraseña, por eso el error es
  UNSUPPORTED_SCHEMA y no PASSWORD_REQUIRED. El archivo SÍ está protegido por
  contraseña (h=1), así que aun con soporte n19 futuro, su apertura quedaría
  PENDING — falta la contraseña (no proporcionada, no probada).
- El nombre ("con contraseña") coincide con la estructura (h=1).

### 2. test_bloqueo_normal_1_aflj.hc
- Tamaño: 4,935 B — SHA-256: `8a69d0fb684b92121451d74ef1da39b4d4b5797f425a5fffdebb81ee7953d71f`
- Sobre: `a=HCCFG`, `b=14`, `c=s1`, `d=h1`, `e=n19`, `f=["ssh","profiles"]`, `n=942`
- Semilla `g`: 32 bytes (hex 64) — SHA-256 prefijo `c2beebc16d747a6c` (solo prefijo, no el valor)
- Protección: `h=0`, sin `k`/`l`/`m` — sin protección por contraseña según el sobre.
- Sin cápsula `p`. Sin slots HWID `o`.
- Sección `i`: label len 1, nonce hex len 48, ct hex len 872. Sin sidecar.
- Secciones `j`: 2 secciones (label len 2, nonce hex len 48).
  - j[0]: ct hex len 1136, con sidecar `d` (nonce hex len 48, ct hex len 48).
  - j[1]: ct hex len 742, sin sidecar.
- Sobre exterior HCX4-v4: OK (autentica).
- Decodificador actual: FAIL, exit 1, stderr exacto:
  `Error al ejecutar el decodificador: HTTP Custom HCCFG: UNSUPPORTED_SCHEMA`
- ⚠️ El nombre ("bloqueo normal") NO coincide con la estructura: `h=0` y sin
  parámetros Argon2 → este archivo no lleva protección por contraseña en el sobre.
  Las longitudes de cifrado de sus secciones son idénticas a las del archivo 1
  (i 872, j 1136+sidecar, j 742; 46 B menos en total, justo lo que ocupan `k`/`l`/`m`
  y el cambio de `h`), lo que sugiere el mismo perfil exportado con y sin contraseña.
  Es una observación de longitudes, no una afirmación de contenido (no se descifró nada).

### 3. test_open_2_7xqg.hc
- Tamaño: 4,529 B — SHA-256: `c180dce9234f7885d52124dea01639da7549cf84e3ae2cc7663c04708371e44c`
- Sobre: `a=HCCFG`, `b=14`, `c=s1`, `d=h1`, `e=n19`, `f=["ssh","profiles"]`, `n=942`
- Semilla `g`: 32 bytes (hex 64) — SHA-256 prefijo `0c01d2ea56751dcb` (solo prefijo, no el valor)
- Protección: `h=0`, sin `k`/`l`/`m` — sin protección por contraseña según el sobre.
- Sin cápsula `p`. Sin slots HWID `o`.
- Sección `i`: label len 1, nonce hex len 48, ct hex len 864. Sin sidecar.
- Secciones `j`: 2 secciones (label len 2, nonce hex len 48).
  - j[0]: ct hex len 1064, sin sidecar.
  - j[1]: ct hex len 654, sin sidecar.
- Sobre exterior HCX4-v4: OK (autentica).
- Decodificador actual: FAIL, exit 1, stderr exacto:
  `Error al ejecutar el decodificador: HTTP Custom HCCFG: UNSUPPORTED_SCHEMA`
- El nombre ("open") coincide con la estructura (h=0, sin contraseña, sin HWID, sin cápsula).

## Comparación con la 934 (archivos de `~/workspace/http-custom-update/drive/`)

Línea base 934 (12 archivos + 2 de solo-HWID): `b=12/e=n15`, `b=12/e=n16`,
`b=13/e=n17`, `b=13/e=n18`, `b=9` (wrapper Access ID), todos `n=934`.

| Aspecto | 934 | 8.1.5 (estos 3) | Cambio |
|---|---|---|---|
| Schema `b` | 12 (n15/n16), 13 (n17/n18), 9 (Access ID) | 14 en los 3 | ✅ Nuevo schema b=14 |
| Schedule `e` | n15, n16, n17, n18 | n19 en los 3 | ✅ Nuevo schedule n19 |
| Build `n` | 934 | 942 | ✅ Nuevo build 942 |
| Cipher `c` / KDF `d` | s1 / h1 | s1 / h1 | Sin cambio |
| Features `f` | `["ssh","profiles"]` | `["ssh","profiles"]` | Sin cambio |
| Semilla `g` | 32 bytes | 32 bytes | Sin cambio de forma |
| Sobre exterior | HCX4-v4 autentica | HCX4-v4 autentica | Sin cambio (misma clave de sobre) |
| Cápsula `p` | Presente solo en b=13 (n17/n18, Extra Protection) | Ausente en los 3 | Ningún archivo 815 trae cápsula `p` |
| Slots HWID `o` | Presentes en n16 y n18 (count 1) | Ausentes en los 3 | Ningún archivo 815 trae slots HWID |
| Protección contraseña | `h=1` + `k=a1, l=2, m=67108864` | Idénticos parámetros en el archivo 1 | Sin cambio de parámetros |
| Secciones | `i` + 2 en `j` | `i` + 2 en `j` | Misma forma; longitudes de ct distintas por perfil |
| Wrapper Access ID (b=9) | 1 archivo (16,231 B) | Ninguno de los 3 | No aparece en esta muestra |

Conclusión de la comparación: el formato exterior es el mismo (HCX4-v4, s1/h1,
`["ssh","profiles"]`, semilla de 32 B, `i` + 2 `j`); lo nuevo es el par
schema/schedule **b=14 / n19** y el build **942**. No hay campos nuevos en el
sobre (mismas claves que 934; `p` y `o` simplemente no aparecen en estos 3).
El decodificador actual solo implementa b=12/n15 y b=10/n11/n12, por eso
rechaza los 3 con UNSUPPORTED_SCHEMA antes de cualquier derivación de clave.

## Pruebas de cordura del decodificador (misma sesión, misma CLI)

- `drive/Test Oppen.hc` (934, b=12/n15, h=0): exit 0 → PASS. El decodificador funciona sobre 934.
- `drive/Test password2.hc` (934, b=12/n15, h=1): exit 1 →
  `Error al ejecutar el decodificador: HTTP Custom HCCFG: PASSWORD_REQUIRED`.
- `drive/Test bloqueo password y hwid.hc` (934, b=12/n16): exit 1 →
  `Error al ejecutar el decodificador: HTTP Custom HCCFG: UNSUPPORTED_SCHEMA`.
  (n16 sigue cerrado en el decodificador actual, como en la línea base.)

## Estado (propuesto / implementado / verificado)

- Verificado: los 3 archivos 815 son HCCFG b=14/n19, build 942; el sobre exterior
  HCX4-v4 autentica en los 3; el decodificador actual los rechaza a los 3 con
  UNSUPPORTED_SCHEMA (probado contra los archivos reales, stdout descartada sin
  leer contenido descifrado).
- Verificado: el archivo 1 lleva protección por contraseña (h=1 + Argon2id);
  los archivos 2 y 3 no (h=0, sin k/l/m).
- No verificado / pendiente: la derivación de clave interior n19 (no existe en
  el decodificador actual); la contraseña del archivo 1 (no proporcionada).
- Propuesto (no implementado): soporte b=14/n19 en el decodificador — fuera
  del alcance de esta tarea de solo lectura.
