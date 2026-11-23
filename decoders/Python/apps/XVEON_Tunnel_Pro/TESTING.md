# XVEON Tunnel Pro — pruebas

## Python

```bash
cd <repo-root>
python3 -m pytest tests/test_xveon.py -v
python3 decoders/Python/apps/XVEON_Tunnel_Pro/xveon.py --self-test
python3 -m py_compile decoders/Python/apps/XVEON_Tunnel_Pro/xveon.py \
  decoders/Python/apps/XVEON_Tunnel_Pro/file_decoder.py tests/test_xveon.py
```

`tests/test_xveon.py` (fixture sintética en
`tests/golden/xveon_vectors.json`, sin credenciales reales) comprueba:

1. `xveon.deobfuscated_constants` devuelve las constantes `Lb1`
   (`XVN1`, `AES/GCM/NoPadding`, `PBKDF2WithHmacSHA256`, `AES`, y la
   concatenación de la passphrase).
2. `encrypt_envelope` → `decrypt_text` round-trip del sobre sintético
   (2 perfiles, ssh + xray) por `xveontunnel://`, por los tres prefijos
   (`xveontunnel://`, `xveon://`, `xvn://`) y como string pelado de
   5 partes (contenido de un `.xveon`).
3. `xveon.decode_file` abre un `.xveon` sintético en disco.
4. Enlace bloqueado (flag `1`): sin contraseña → `NeedsPassword`;
   contraseña incorrecta → `XveonError`; contraseña correcta (truncada
   a 15 caracteres como la app) → sobre original.
5. Ciphertext manipulado → rechazo por autenticación GCM.
6. Entradas inválidas (vacío, flag `2`, esquema ajeno) → `XveonError`.
7. `summarize` expone host/puerto ssh, proxy y protocolo xray.
8. `file_decoder.decode` / `run` / `decode_text`: documento
   `{"application", "extension"|"protocol", "config"}`; `decode_text`
   devuelve `None` para esquemas ajenos; bloqueado sin contraseña →
   `XveonDecodeError` con `code == "PASSWORD_REQUIRED"`; bloqueado con
   contraseña incorrecta → `code == "AUTH_FAILED"`.
9. CLI `file_decoder.py <archivo>`: salida JSON en stdout, exit 0;
   bloqueado sin contraseña → `{"workerError": "PASSWORD_REQUIRED"}`
   en stdout, exit 3; contraseña por stdin (JSON `{"password": ...}`)
   abre el archivo bloqueado.
10. Estructura del sobre real (evidencia interna del expediente,
    `tests/evidence/real_link_decrypted.json` en el dossier local, NO
    en el repo): v2, modo ssh, 1 perfil. Sin re-descifrar.

Chequeo en vivo opcional (NO corre por defecto; la URI real nunca se
guarda en el repo):

```bash
XVEON_REAL_URI='xveontunnel://...' python3 -m pytest tests/test_xveon.py -v -k real_link
```

## Ruta worker (verificación local con el harness del expediente)

Con los JSON de registro ya parcheados (ver `edits-xveon.md`):

```bash
python3 cloud/workers/python/engine.py  # no CLI; usar decode_file/decode_text
```

Verificado en el harness local (ver dossier `RESULTS.md`):

- `engine.decode_file("xveon", raw)` y `("xvn", raw)` abren el
  `.xveon`/`.xvn` sintético por la ruta supplied (`supplied_bridge`,
  `file_decoder.decode` genérico, sin rama por app).
- `engine.decode_file("xveon", raw, credentials={"password": ...})`
  abre el archivo bloqueado; sin contraseña → `PASSWORD_REQUIRED`.
- `engine.decode_text("xveontunnel://...")` y
  `text_bridge.dispatch(...)` abren el enlace sintético y el enlace
  real (solo estructura: v2, 1 perfil ssh; sin credenciales en salida);
  `xveon://` y `xvn://` igual.
- `text_bridge.dispatch("vmess://...")` sigue devolviendo `None`
  (sin regresión en otros esquemas).

## Node

```bash
cd cloud/web && node --test tests/xveon-tunnel-pro.test.mjs
```

`tests/xveon-tunnel-pro.test.mjs` comprueba las entradas nuevas en
`publicFormats()` (`xveon`, `xvn`) y `publicTextFormats()` (los tres
esquemas), que `catalog().apps` NO incluye `xveon-tunnel-pro`
(`FILE_ONLY`, sin tarjeta), que la entrada existe en
`SUPPLIED_INTEGRATIONS` con `catalogState: "FILE_ONLY"` y
`requests: []`, y que el payload del catálogo no contiene las cadenas
prohibidas (`decoders/Python/`, `"script":`, `source_script`,
`privateKey`, ...).

Los suites compartidos (`file-formats`, `text-format-catalog`,
`server-vpn-catalog`) se corren en el árbol del coordinador tras
aplicar `edits-xveon.md`; los pines que cambian son:

- `text-format-catalog.test.mjs`: `published.formats.length` 279 → 281.
- `supplied-integrations.mjs`: inventario 82 → 83 apps.
- `CATALOG_VERSION` 97 → 98 (lo sube el coordinador, una vez por lote).

## Pendiente (no cubierto aquí)

- Archivo `.xveon` real exportado por la app (estado actual de
  archivos: `VERIFIED_SYNTHETIC`).
- Enlace real `xveon://` o `xvn://` (prefijos verificados solo con
  round-trip sintético).
- Enlace real bloqueado (flag `1`) — la ruta de contraseña es
  sintética hasta ahora.
- Prueba en VPS tras el despliegue autorizado (`update all`).
