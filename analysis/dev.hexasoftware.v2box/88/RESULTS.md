# V2Box 6.2.3 (build 88) — RESULTADOS 2026-11-19

Entorno: Python 3.12.3, `pycryptodome` 4.5.0 (solo tests; el
decodificador operativo es stdlib puro). Worktree en el head remoto
`9b2e9b31` (`ci/unity-ads-online-qa`).

## Archivo real (estructura y códigos; NUNCA valores)

- Ruta (fuera de Git): `~/workspace/user/files/
  TheBestVIP_Free_MF____v_box__________0_cp2p.v2box`
- Tamaño 1.736 B; SHA-256
  `3130faa92b3c4ccad963f7ef080e8e73e936207b76ace59aefa4116c832dd250`
- Sobre: `magic "v2box_export"`, `version 2`, header `{createdAt:
  1794572716, kdf: "none", v: 2}` (creado 2026-11-13T12:25:16Z),
  nonce 12 B, tag 16 B, ciphertext 1.164 B.
- Antes de la corrección: `TAG_MISMATCH` (reproducido con el
  decodificador del head).
- Después de la corrección: `status ok`, `format v2box_export`,
  `version 2`, `kdf none`, `aad header-b64`; payload con claves
  `configs`, `lockMessage`, `locked`; 1 config tipo `profile`;
  `subscription` None; `locked` true; `warnings` [].
- Verificado por dos vías: decodificador directo
  (`V2Box_archivos.py`) y vía del servidor
  (`supplied_bridge.file_decode("v2box", ...)` → mismo resultado).

## Clave fija (verificación, sin publicar valores nuevos)

- Los 32 bytes ofuscados (XOR 90) del expediente 88 están presentes
  en `classes.dex` del APK local 6.2.3/88 (offset 3734104) y derivan
  la clave documentada. La clave NO rotó.
- Play sigue en 6.2.3 (AppBrain/Uptodown, actualizada 2026-10-29);
  no hay 6.2.4/6.3 de Android. Hipótesis "clave rotada" REFUTADA.

## Pruebas ejecutadas

- `V2Box_archivos.py --self-test`: **9/9 OK** (antes 7/7).
- `tests/test_v2box_aad.py` (nuevo): **5/5 OK** — v2 none con AAD
  header-b64, fallback header-bytes, AAD incorrecto → TAG_MISMATCH,
  v1 sin contraseña (round-trip), v2 pbkdf2 con AAD header-b64.
- `tests/test_v2box_password.py` (worker bridge, sin cambios): **5/5 OK**.
- `M_Light.py --self-test`: 5/5 OK; `M_Light_archivos.py
  --self-test`: 6/6 OK (regresión Pausa VPN, sin cambios).
- `py_compile` OK en los archivos modificados.

## Pausa VPN / M Light — re-corrida en vivo 2026-11-19 (trabajo separado)

- Petición exacta de la app: `GET
  https://raw.githubusercontent.com/PausaStudio/pausada258/refs/heads/main/config.json`
  con `User-Agent: Dalvik/2.1.0` → HTTP 200, 1.019.591 B en 1,17 s.
- Descifrado con `M_Light.py --raw`: catálogo **v1.0.115, 117
  servidores**, 40 MyServer distintos, 3.814 campos (1.984 no
  vacíos), 137.766 B.
- SHA-256 del JSON descifrado:
  `7e61c89fc62cb9fd162df2aabd5260b608e262e2ba6f6ef3840d40dae4cc0cd1`
  — **byte-idéntico** a la muestra verificada el 2026-11-17.
- El JSON de resultado NO contiene APIs de descarga (sin
  `raw.githubusercontent`, `github.com`, `pausada258` ni `PausaStudio`
  como URL; una única mención en minúsculas de `pausastudio` dentro
  de un valor de campo, no una URL).
- Cableado ya presente en la rama: `supplied-integrations.json` id
  `m-light`, `catalogState CONNECTED`; `file-formats.json` (sufijo
  `pausa`); `text-formats.json` (`pausa://`). **No se reintegra nada:
  ya estaba cableado y verificado en vivo.**
- Pendiente (sin cambios): archivo `.pausa` real y enlace `pausa://`
  real. Nota: `verify_provider.py m-light` falla en un assert
  preexistente (el módulo `M_Light.py` no expone
  `decode`/`decode_json_bytes`/`decode_blob_text`/`run`; solo CLI):
  limitación conocida de esa herramienta, no del proveedor; la
  verificación se hizo con `M_Light.py` directamente, como en el
  expediente original.

## Negativos / pendientes

- Sin archivo `.v2box` v1 real ni `v2box://locked=` real.
- Sin archivo v2 `ecdh-p256` real (necesita la clave privada P-256
  del dispositivo destinatario, no exportable del Keystore).
- Despliegue al VPS pendiente de Pedro (`spdecode update all`;
  ver REPRODUCE.md). La corrección vive en `V2Box_archivos.py`, que
  corre en el worker: `update api` NO basta.
