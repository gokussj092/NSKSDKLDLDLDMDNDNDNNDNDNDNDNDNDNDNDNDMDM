# XU Tunnel 6.0 — pruebas

## Python

```bash
cd <repo-root>
python3 -m unittest tests.test_xutunnel -v
python3 decoders/Python/apps/XU_Tunnel/xutunnel_archivos.py --self-test
python3 -m py_compile decoders/Python/apps/XU_Tunnel/xutunnel_archivos.py \
  tests/test_xutunnel.py
```

`tests/test_xutunnel.py` (11 tests; el vector es el `TEST_VECTOR` del
propio módulo, construido con el método CBC verificado, sin
credenciales reales) comprueba:

1. El vector de prueba descifra a `ExpireDate` 1798761600000,
   `CFGMessage "Test config"`, `SNIHost "example.com"`,
   `ProxyPort "8080"`, `isPassON false`; `run` devuelve el mismo
   documento como JSON.
2. La salida descifrada no contiene las cadenas prohibidas
   (`decoders/Python/`, `"script":`, `source_script`, `privateKey`).
3. Round-trip con PyCryptodome (solo para construir vectores; el
   descifrador es stdlib puro) con los dos prefijos de nombre de app
   (`"XU Tunnel VPN"` y `"XU Tunnel"`).
4. Prefijo ajeno → `WRONG_DOCUMENT`; clave incorrecta → rechazo;
   `run` devuelve `None` (sin resultado parcial).
5. Rechazos sin resultado parcial: vacío, Base64 inválido, vector
   truncado, último byte corrupto, `<html/>`, entrada mayor que
   `MAX_BYTES`.
6. Saltos de línea Base64 (`\r\n` cada 64 caracteres) se aceptan,
   como lee la app el archivo línea a línea.
7. CLI fuera del checkout (`cwd=/tmp`): `--self-test` exit 0 con
   `self-test OK`; `--file` con el vector exit 0 y stdout JSON exacto,
   stderr vacío; archivo ausente o con contenido privado → exit 1,
   stdout vacío y sin eco del contenido en stderr.
8. Ruta worker: `engine.decode_file("xu", …)` devuelve el perfil
   completo (`isPartial: false`, `structuredJson` y `rawText` iguales
   al documento), sin cadenas prohibidas.
9. El worker rechaza el vector corrupto con `DECODE_FAILED` y
   rechaza credenciales innecesarias con `CREDENTIALS_NOT_ALLOWED`
   (el `.xu` no necesita credenciales: no hay edición de allowlist
   en `engine.py`).
10. Registro: `load_file_engines()` sigue en 240 rutas C0 (`.xu` no
    es C0); `load_runtime_file_engines()` incluye `"xu"` con
    `source` `.../apps/XU_Tunnel/xutunnel_archivos.py` y `phase`
    `"C8"`; `file-formats.json` tiene la entrada exacta
    (`XU Tunnel VPN 6.0`, `offlineSupported: false`,
    `cloudSupported: true`, `credentialFields: []`) y
    `supplied-integrations.json` tiene `xu-tunnel` con
    `catalogState: "FILE_ONLY"`, `requests: []`,
    `extensions: ["xu"]`, `fileModule: "xutunnel_archivos.py"`,
    `textPrefixes: []` y sin `catalogModule`.
11. Catálogo: `engine.decode_provider_catalog("xu-tunnel", …)`
    falla cerrado con `DECODE_FAILED` (FILES ONLY: sin broker, sin
    módulo de catálogo, sin tarjeta).

Regresión conocida del entorno, no causada por este cambio: bajo el
Python del sistema, el test hermano `tests/test_hex_tunnel.py` falla
porque PyCryptodome vive en user-site y el hijo del engine
(`_child_env`) sobrescribe `HOME`; pasa 10/10 bajo el venv de
`~/workspace/http-custom-update`. El descifrador XU es stdlib puro y
sus 11 tests pasan con ambos intérpretes.

## Ruta worker (verificación local con el harness del expediente)

Con los JSON de registro ya parcheados (ver `edits-xu.md`):

```bash
python3 -m unittest tests.test_cloud_c8_vpn_registry -v
python3 -m unittest tests.test_xutunnel -v
```

Verificado en el harness local (copias de los archivos de head +
archivos staged, sin tocar el árbol compartido):

- `load_runtime_file_engines()` pasa de 279 rutas a 280; el pin
  `270` de `tests/test_cloud_c8_vpn_registry.py` estaba ya obsoleto
  en head (279 medido antes del cambio) y se actualiza a 280.
- `engine.decode_file("xu", …)` abre el vector por la ruta
  supplied (`FILE_ROUTES`, derivada de `supplied-integrations.json`,
  apunta al mismo módulo que la entrada `_C8_FILE_ENGINES`).
- `decode_provider_catalog("xu-tunnel", …)` falla cerrado con
  `DECODE_FAILED`, nunca devuelve un catálogo parcial.

## Node

```bash
cd cloud/web && node --test tests/file-formats.test.mjs
```

`tests/file-formats.test.mjs` (9 tests, incluido el nuevo test XU)
comprueba, entre otros, que todas las rutas C0 y C8 se publican una
vez (`current.length == known.size`, 280 tras el cambio), la
precedencia de extensiones, el contrato de versión del catálogo y el
esquema. El nuevo test XU (modelo del test de Hex Tunnel) comprueba
la entrada `xu` en `publicFormats()` (`XU Tunnel VPN 6.0`,
`offlineSupported: false`, `cloudSupported: true`,
`credentialFields: []`), que la respuesta del catálogo la incluye y
que `catalog().apps` NO incluye `xu-tunnel` (FILE_ONLY, sin tarjeta).

Los suites compartidos se corren en el árbol del coordinador tras
aplicar `edits-xu.md`; los pines que cambian son:

- `file-formats.json`: 279 → 280 formatos.
- `supplied-integrations.json`: 82 → 83 apps.
- `supplied-integrations.mjs`: inventario 82 → 83 apps.
- `supplied-integrations.test.mjs`: `SUPPLIED_INTEGRATIONS.length`
  82 → 83.
- `test_cloud_c8_vpn_registry.py`: rutas runtime 270 → 280 (el pin
  270 ya estaba obsoleto en head; medido 279 antes, 280 después).
- `text-format-catalog.test.mjs`: `published.formats.length`
  279 → 280.
- `CATALOG_VERSION` 97 (no cambia en este cambio: no hay tarjeta;
  el coordinador lo sube una vez por lote si hace falta).

Verificado en el harness local (cuatro suites juntas, tras aplicar
`edits-xu.md` a copias de head):

- `file-formats.test.mjs`: 9/9.
- `supplied-integrations.test.mjs`: 7/7.
- `server-vpn-catalog.test.mjs`: 39/39.
- `text-format-catalog.test.mjs`: 3/3.
- Total: 58/58, 0 fallos.

## Pendiente (no cubierto aquí)

- Archivo `.xu` real exportado por la app (estado actual de
  archivos: `VERIFIED_SYNTHETIC`; el prefijo exacto del nombre de
  app — `"XU Tunnel VPN"` frente a `"XU Tunnel"` — se infiere del
  hermano XUI Tunnel y falta confirmarlo con un `.xu` real).
- Catálogo en vivo v1.3.40: NO integrado (descarga en vivo imposible,
  token de `deeptun.xyz` desconocido; 39 valores sin descifrar).
  `xutunnel.py` y `catalog-live-v1.3.40.json` no forman parte de esta
  entrega.
- Prueba en VPS tras el despliegue autorizado (`update all`).
