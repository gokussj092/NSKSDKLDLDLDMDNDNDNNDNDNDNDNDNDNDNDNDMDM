# Verificación de la fusión HC 942 (n19) — 2026-11-26 (Tijuana)

Fusión en staging: `~/workspace/repo-integration/staging-hc942/` (sin commit,
sin push, sin tocar el worktree). Venv:
`~/workspace/http-custom-update/venv/bin/python`. Árbol de pruebas:
`/tmp/hc942-testtree` (copia del repo + archivos de staging superpuestos).

## Archivos fusionados (únicos cambios de código)

- `decoders/Python/apps/HTTP_Custom/crypto.py` — `N19_INNER_STATE`,
  `N19_OUTER_STATE`, `native_fold_n19()` (misma construcción que n15,
  prefijo 0xf1, digest de certificado sin cambio).
- `decoders/Python/apps/HTTP_Custom/codec.py` — `_derive_n19()` (AAD
  `HCCFG|14|…|n19|…`, HKDF `hc-config-content-v14`), despacho en `derive()`
  para b=14/e=n19, `_skey` con etiqueta `hc-config-part-v12` también para
  n19, `app_version` "8.1.5 (942)", `V4_PROTECTION_KEY_MAP` +
  `BANNER_KEY_MAP` con expansión del `tunnelBanner` anidado solo para n19.
- Sin cambios: `HTTPCUSTOM.py`, `_hc_hccfg.py`, `hc_bridge.py` (ya enrutan
  por el motor moderno), `decoders.json`, `android/`, `switches.json`,
  `C0_FORMAT_MATRIX.csv`, updater del bot.
- NO importado (regla de Pedro 2026-11-26): `_parse_auth_inputs`,
  `_extract_hwid_value` ni el manejo de contraseña/HWID de `run()` del
  script nuevo. La contraseña/HWID sigue por `_parse_auth` y la taxonomía
  `HCError` interna (`PASSWORD_REQUIRED` / `HWID_REQUIRED` /
  `HWID_PASSWORD_REQUIRED` / `AUTH_FAILED`) y el flujo de credenciales
  pendientes del bot. Sin casos sin cubrir detectados.

## Positivos (archivos reales, sin credenciales en este dossier)

| Archivo | Resultado |
|---|---|
| `test_open_2_7xqg.hc` | ABRE — `8.1.5 (942)`, 2 perfiles (labels s0, c0), banner `{"version": 1, "style": "custom", "content": "annsksk"}` |
| `test_bloqueo_normal_1_aflj.hc` | ABRE — `8.1.5 (942)`, 2 perfiles (labels s0, c0), mismo banner expandido |
| `test_bloqueo_normal_con_contrase_a_0_m46a.hc` (sin credencial) | `PASSWORD_REQUIRED` (vía `codec.decrypt` y vía `hc_bridge.py` → `{"workerError": "PASSWORD_REQUIRED"}`, exit 3) |
| mismo archivo, contraseña incorrecta | `AUTH_FAILED` (la ruta Argon2id + HKDF v14 autentica; no abre con credencial errónea) |

Comprobado en los 3 puntos de entrada: `codec.decrypt`,
`HTTPCUSTOM.run` y `apps/HTTP_Custom/file_decoder.run` (los 3 abren los 2
archivos h=0 con el mismo resultado), y `cloud/workers/python/hc_bridge.py`
(con `PYTHONPATH` al árbol de pruebas; JSON con `app_version` 8.1.5 (942)).

## Regresión n15/934 y formatos antiguos

- `drive/Test Oppen.hc` (934 real, b=12/n15, h=0): ABRE, `8.0.22 Patch 2
  (934)`, 2 perfiles. Salida JSON **byte-idéntica** entre el codec del
  worktree (sin modificar) y el fusionado.
- Suite HC del repo (`tests/test_http_custom_899.py`,
  `tests/test_hc_legacy57.py`, `tests/test_hc_sip_new_variants.py`,
  `tests/test_offline_hc_native_parity.py`): **23 passed, 82 subtests
  passed, 5 failed — idéntico en el worktree intacto y en el árbol con la
  fusión**. Los 5 fallos son preexistentes y ajenos al cambio:
  `RuntimeError: C8 engine unavailable` (motor nativo C8 no construido en
  este entorno) en `test_cloud_worker_all_lock_modes_and_safe_errors` y
  `test_cloud_worker_keeps_structure_and_reports_unresolved_fields`.
- `py_compile` de `codec.py` y `crypto.py` fusionados: OK.

## Negativos

| Archivo | Resultado (fusionado) | Antes (worktree) |
|---|---|---|
| `test_solo_whid_1_7zzx.hc` (n16) | `UNSUPPORTED_SCHEMA` | igual |
| `test_solo_whid_y_pass_0_k9v4.hc` (n16) | `UNSUPPORTED_SCHEMA` | igual |
| `Gjost_0_d9lo.hc` | `HWID_REQUIRED` | igual |
| `test_bloqueo_normal_con_contrase_a_0_m46a.hc` | `PASSWORD_REQUIRED` | `UNSUPPORTED_SCHEMA` (antes no llegaba a la derivación) |
| `884_0_wvd2.hc` | `HTTPCUSTOM.run` → `ValueError: HTTP Custom HCCFG: Unsupported schema b=8`; `hc_bridge` → `{"workerError": "DECODE_FAILED"}` exit 3 — **idéntico al worktree intacto** | igual |

## Ruta de textos hccloud://

- `hccloud://playsmarty/<alias>` → `https://link.playsmarty.uk/<alias>`;
  `hccloud://mrfrank/<alias>` → `https://cloudvpn.mrfrankofc.com/<alias>`
  (`parseHttpCustomLegacyReference`, `cloud/web/lib/c35-provider.mjs`).
- `importHttpCustomReference` descarga los bytes y los devuelve **sin
  reescribirlos** ("Latin1/UTF-8 carriers are handled by the existing
  codec"); verificado con stub de descarga sobre el archivo 942 real:
  bytes idénticos (4,529 B) y el codec fusionado los abre. El texto es
  solo una referencia/alojamiento del .hc; no hay decodificador de texto
  separado que tocar.
- Tests JS (`cloud/web/tests/http-custom-online.test.mjs`,
  `text-format-catalog.test.mjs`): **14 pass, 3 fail**. Los 3 fallos son
  preexistentes y ajenos a esta fusión (Python): `INVALID_ORIGINAL_ICON`
  al cargar el icono del catálogo en `server-vpn-catalog.mjs`. Pasan las
  pruebas HC relevantes, entre ellas "new HC import downloads and decodes
  once in one authenticated operation" y "pasted HTTP reference passes
  exact ciphertext, password and HWID through the canonical HC worker".

## Pendientes

1. Contraseña del archivo `test_bloqueo_normal_con_contrase_a_0_m46a.hc`
   (no proporcionada): la ruta n19 protegida está implementada y verificada
   con contraseña incorrecta (`AUTH_FAILED`), pero falta una apertura real
   con la contraseña correcta.
2. n16/n17/n18 y b=9 siguen cerrados (por diseño; sin cambios).
3. El `tunnelBanner` de archivos 934 (n15) sigue sin expandirse (clave
   `x` con el mapa histórico) por decisión de alcance: n15 se mantuvo
   byte-idéntico. Si se quiere la misma expansión para 934, es extender
   `_norm_prot_v4` a n15 — decisión pendiente.
4. Metadatos no tocados en esta fusión (corresponden al paso de merge):
   `decoders/Python/apps/HTTP_Custom/manifest.json` (motor y formatos),
   README/TESTING del app, y registros de formatos en la nube.
