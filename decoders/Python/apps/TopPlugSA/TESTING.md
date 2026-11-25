# TOP-PLUG-SA VPN 0.29.26 — pruebas

## Python

```bash
cd <repo-root>
python3 -m unittest tests.test_topplugsa -v
python3 decoders/Python/apps/TopPlugSA/topplugsa.py self-test
python3 -m py_compile decoders/Python/apps/TopPlugSA/topplugsa.py \
  tests/test_topplugsa.py
```

`tests/test_topplugsa.py` (13 tests; los vectores se construyen con el
propio módulo y con PyCryptodome solo para cifrar vectores de prueba; el
decodificador necesita PyCryptodome en runtime) comprueba:

1. Round-trip TOPPLUG4: el documento sintético descifra a su perfil
   (`server "example.com"`, `ssh_mode "direct_tls"`); `run` devuelve el
   mismo documento como JSON.
2. Round-trip TOPPLUG5 con contraseña: descifra a `kind "password-v5"`;
   sin contraseña → `PASSWORD_REQUIRED`; contraseña corta (<12) →
   `INVALID_CREDENTIALS`; contraseña incorrecta → `AUTH_FAILED`.
3. TOPPLUG1 sintético: vector firmado con clave P-256 generada verifica
   y descifra a su perfil.
4. TOPPLUG2 sintético: la firma verifica y se devuelven los metadatos
   (`kind "sealed-v3-device-bound"`, `device_locked true`), pero el
   perfil es **siempre `None`**: device-bound, nunca se descifra.
5. TOPPLUG-MANUAL-V2 sintético en claro.
6. La salida descifrada no contiene las cadenas prohibidas
   (`decoders/Python/`, `"script":`, `source_script`, `privateKey`).
7. Rechazos sin resultado parcial: vacío, texto sin cabecera, Base64
   inválido, vector truncado, último byte corrupto, `<html/>`, entrada
   mayor que `MAX_BYTES`, versión no soportada.
8. CLI fuera del checkout (`cwd=/tmp`): `self-test` exit 0
   (9 comprobaciones; las 2 de muestra real y la de vivo saltan sin red
   ni fixture); modo directo con el vector exit 0 y stdout JSON exacto,
   stderr vacío; archivo ausente o con contenido privado → exit 1,
   stdout vacío y sin eco del contenido en stderr.
9. CLI con TOPPLUG5: sin contraseña por stdin → exit 3 con
   `{"workerError": "PASSWORD_REQUIRED"}`; con la contraseña → exit 0
   y perfil completo.
10. Ruta worker: `engine.decode_file("tpc", …)` devuelve el perfil
    completo (`isPartial: false`, `structuredJson` y `rawText` iguales
    al documento), sin cadenas prohibidas.
11. El worker rechaza el vector corrupto con `DECODE_FAILED`, un TOPPLUG5
    sin contraseña con `PASSWORD_REQUIRED`, con contraseña incorrecta
    con `AUTH_FAILED`, y credenciales innecesarias con
    `CREDENTIALS_NOT_ALLOWED` (el `.tpc` solo admite `password`).
12. Registro: `load_file_engines()` sigue en 240 rutas C0 (`.tpc` no
    es C0); `load_runtime_file_engines()` incluye `"tpc"` con
    `source` `.../apps/TopPlugSA/topplugsa.py` y `phase` `"C8"`;
    `file-formats.json` tiene la entrada exacta
    (`TOP-PLUG-SA VPN 0.29.26`, `offlineSupported: false`,
    `cloudSupported: true`, `credentialFields: ["password"]`) y
    `supplied-integrations.json` tiene `top-plug-sa` con
    `catalogState: "FILE_ONLY"`, `requests: []`,
    `extensions: ["tpc"]`, `fileModule: "topplugsa.py"`,
    `textPrefixes: []` y sin `catalogModule`.
13. Catálogo: `engine.decode_provider_catalog("top-plug-sa", …)`
    falla cerrado con `DECODE_FAILED` (FILE_ONLY: sin broker, sin
    módulo de catálogo, sin tarjeta).

## Ruta worker (verificación en el árbol del coordinador)

```bash
python3 -m unittest tests.test_cloud_c8_vpn_registry -v
python3 -m unittest tests.test_topplugsa -v
```

- `load_runtime_file_engines()` pasa de 282 rutas a 283.
- `engine.decode_file("tpc", …)` abre el vector por la ruta
  supplied (`FILE_ROUTES`, derivada de `supplied-integrations.json`,
  apunta al mismo módulo que la entrada `_C8_FILE_ENGINES`).
- `decode_provider_catalog("top-plug-sa", …)` falla cerrado con
  `DECODE_FAILED`, nunca devuelve un catálogo parcial.

## Node

```bash
cd cloud/web && node --test tests/file-formats.test.mjs
```

`tests/file-formats.test.mjs` (10 tests, incluido el nuevo test
TOP-PLUG-SA) comprueba, entre otros, que todas las rutas C0 y C8 se
publican una vez (`current.length == known.size`, 283 tras el cambio),
la precedencia de extensiones, el contrato de versión del catálogo y el
esquema. El nuevo test TOP-PLUG-SA (modelo del test de XU Tunnel)
comprueba la entrada `tpc` en `publicFormats()`
(`TOP-PLUG-SA VPN 0.29.26`, `offlineSupported: false`,
`cloudSupported: true`, `credentialFields: ["password"]`), que la
respuesta del catálogo la incluye y que `catalog().apps` NO incluye
`top-plug-sa` (FILE_ONLY, sin tarjeta).

Los suites compartidos se corren en el árbol del coordinador tras
aplicar el staging; los pines que cambian son:

- `file-formats.json`: 282 → 283 formatos.
- `supplied-integrations.json`: 84 → 85 apps.
- `supplied-integrations.mjs`: inventario 84 → 85 apps.
- `supplied-integrations.test.mjs`: `SUPPLIED_INTEGRATIONS.length`
  84 → 85.
- `test_cloud_c8_vpn_registry.py`: rutas runtime 282 → 283.
- `text-format-catalog.test.mjs`: `published.formats.length`
  282 → 283.
- `CATALOG_VERSION` 98 (no cambia en este cambio: no hay tarjeta;
  el coordinador lo sube una vez por lote si hace falta).

## Verificado en esta preparación (sin el árbol completo del repo)

- `py_compile` de `topplugsa.py` y `tests/test_topplugsa.py`: OK.
- `topplugsa.py self-test`: 7/9 OK, 2 saltados (muestras reales no
  incluidas en el repo), 0 fallos; con red, el vivo también pasa
  (verificado por separado).
- Tests puros del decodificador (`test_topplugsa.py`, sin la ruta
  worker): 9/9 OK.
- Comprobaciones estáticas sobre las copias del head: orden de
  `file-formats.json` válido (`.tpc` entre `tnl` y `tpp`), conteos
  282 → 283 y 84 → 85, unicidad de sufijos e ids, entrada `_C8`
  con el formato exacto que exige el regex de `file-formats.test.mjs`,
  `FILE_ROUTES` derivaría `tpc → top-plug-sa`.
- NO verificado aquí (falta el árbol completo del repo en este
  entorno): la ruta worker `engine.decode_file("tpc", …)`, los
  suites Node (`file-formats`, `supplied-integrations`,
  `server-vpn-catalog`, `text-format-catalog`) y el despliegue.
  El coordinador debe correrlos al aplicar el staging.

## Pendiente (no cubierto aquí)

- Archivo `.tpc` real exportado por la app (TOPPLUG1, MANUAL-V2 o
  TOPPLUG5 con su contraseña) para pasar esas variantes de sintético
  a VERIFIED_REAL. La muestra real TOPPLUG4 del APK no se incluye en
  el repo (lleva credenciales).
- TOPPLUG2 no se puede cerrar sin el teléfono dueño (device-bound).
- Catálogo vivo (3 JSON públicos): NO integrado como proveedor (son
  contacto/precios/avisos, no un catálogo multi-servidor).
- Prueba en VPS tras el despliegue autorizado (`update all`).
