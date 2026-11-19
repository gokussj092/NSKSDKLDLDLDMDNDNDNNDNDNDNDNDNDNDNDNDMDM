# Resultados — 1FTunnel 0.7.3 (build 129)

Fecha: 2026-11-19. Estado del expediente: **PARTIAL**.

## Resumen

| Pregunta | Respuesta |
|---|---|
| ¿Cambió el método en 0.7.3? | **No.** Mismo envelope 1FT1 v1–v3, misma KDF/ROOT_KEY/etiquetas, mismo CFG1 (máx. v6), mismos enums y modelos. |
| ¿Por qué no abría el archivo de Pedro? | Está protegido con contraseña (`lockMode 2`): sin ella, `PASSWORD_REQUIRED`. |
| ¿Abre con la contraseña? | **Sí** con el decodificador del repo (`1FTunnel.py`): GCM autenticado, CFG1 v6, SSH + SlowDNS. |
| ¿Lo abriría el servidor (online)? | **No, hoy no (código actual)**: la ruta del worker (`file_decoder.py` → `codec.py`) rechaza CFG1 v6 con `UNSUPPORTED_PAYLOAD_VERSION` incluso con la contraseña correcta. **Sí tras la corrección** (ver §5): `codec.py` acepta v1–v6 y la ruta worker abre el archivo real v6. Falta redesplegar el worker. |
| ¿Lo abriría la offline? | No: `.1ftnl` no está soportado y el propietario eligió ONLINE ONLY. |

## Pruebas ejecutadas

### 1. Archivo real de Pedro (Free-23_0_jn8j.1ftnl, 1.690 B)

Herramienta: `tools/verify_073.py` (contraseña solo vía `ONEFT_PW`).

| Comprobación | Resultado |
|---|---|
| Envelope 1FT1 v3, algo 1, kdf 1; AAD 122 + ct 1.101 = 1.267 B exactos | OK |
| Sin contraseña → `PASSWORD_REQUIRED` | OK |
| Con contraseña, `1FTunnel.py`: `authenticated: True`, configType SSH, lockMode 2, keySlot 1, minBuild 129, CFG1 v6, ssh+inject(SLOWDNS)+slowDns | OK |
| Con contraseña, ruta worker `file_decoder.py` → `UNSUPPORTED_PAYLOAD_VERSION` | OK (reproduce el fallo del servidor) |
| Etiquetas KDF nativas idénticas en ambas `.so` (v1/v2, sin v3) | OK |
| **verify_073.py sobre el archivo real** | **ALL OK** |

### 2. Suite del expediente (8 tests, sintéticos)

`python -m unittest discover -s analysis/com.oneftunnel.app/129/tests`

| Test | Resultado |
|---|---|
| Repo self-test 12/12 (`1FTunnel._self_test`) | OK |
| Fixture v6+contraseña abre (CFG1 v6, SSH, SLOWDNS, recordType A) | OK |
| Fixture sin contraseña → `PASSWORD_REQUIRED` | OK |
| Fixture con contraseña mala → `AUTH_FAILED` | OK |
| Ruta worker ABRE la fixture v6 (antes: `UNSUPPORTED_PAYLOAD_VERSION`) | OK (tras la corrección) |
| Ruta worker abre fixtures v1–v5, sin regresión (5 subtests) | OK |
| Fixture alterada (1 byte) → `AUTH_FAILED` | OK |
| Fixture coincide con el JSON esperado (SHA-256 `aa4c451b…`) | OK |
| **Total** | **8/8 OK** |

### 5. Corrección del servidor — `codec.py` acepta CFG1 v1–v6 (2026-11-19)

Autorizada por el propietario ("Sí, corrígelo y redespliega", 2026-11-19 ~00:41).
Opción elegida: **alinear `codec.py` con `1FTunnel.py`** (no cambiar el import
de `file_decoder.py`, para no ampliar lo que el worker acepta más allá de
archivos 1FT1: `1FTunnel.decode` es un despachador que también acepta
locked-v2, 1FTlb, backups y enlaces JSON en claro, con otras formas de
salida).

Cambios en `decoders/Python/apps/OneFTunnel/codec.py` (único archivo de
código tocado):

| Cambio | Detalle |
|---|---|
| `parse_config`: `range(1, 6)` → `range(1, 7)` | Acepta CFG1 v1–v6 |
| Modos inject: se añade `"SLOWDNS"` (índice 5, al final) | Igual que `INJECT_MODES` de `1FTunnel.py` |
| Sección SlowDNS solo si `version >= 6` | `{resolver, nameserver, publicKey, recordType}` con `SLOWDNS_RECORD_TYPES` |
| Clave `"slowDns"` solo en v6 | A propósito: en v1–v5 la salida JSON queda **byte-idéntica** a la anterior (sin la clave), como fija `tests/golden/oneftunnel_vectors.json` |
| Docstring del módulo | Anota CFG1 v1–v6 |

Verificación de la corrección (antes del push):

| Comprobación | Resultado |
|---|---|
| `parse_config` de `codec.py` ≡ `1FTunnel.py` (salvo formato de líneas) | OK (diff solo de saltos de línea) |
| Ruta worker abre el archivo real v6 con contraseña: `authenticated: True`, `isPartial: False`, CFG1 v6, SLOWDNS | OK |
| Ruta worker sin contraseña → `PASSWORD_REQUIRED` | OK |
| Suite del expediente 8/8 (incl. v1–v5 por la ruta worker) | OK |
| `verify_073.py` sobre el archivo real y la fixture v6 | **ALL OK** (ambos) |
| Repo self-test 12/12 (`1FTunnel._self_test`) | OK |
| `tests/test_oneftunnel.py` (repo): 8 tests, 1 fallo **preexistente** | `test_complete_isolated_file_text_routes_and_bot_registration` falla igual en código prístino: `len(routes) == 276`, el test espera 270 (registro de rutas creció por otro trabajo; ajeno a esta corrección, no tocado) |
| Fixtures v1–v5 (`tools/make_fixtures_v1_v5.py`): `codec.decode` ≡ `1FTunnel.decode` en cada versión (salvo la clave `slowDns`, ausente en codec < v6 por diseño) | OK |

**Pendiente:** redespliegue del worker en el VPS (`spdecode update all`) y
prueba de extremo a extremo en la app online por el propietario.

### 3. Comparación 0.7.1 vs 0.7.3

| Comparación | Resultado |
|---|---|
| APK: package `com.oneftunnel.app`; 0.7.1 = v0.7.1/127; 0.7.3 = v0.7.3/129 | OK |
| classes2.dex byte-idéntica (`4b456639…`) | OK |
| Clases `com.oneftunnel.app.*`: mismo conjunto (sin altas ni bajas) | OK |
| Enums: InjectMode 6, SlowDnsRecordType 9, ConfigType 4, XrayProtocol 5 — idénticos | OK |
| Tokens de formato nuevos en 0.7.3: solo mensajes SlowDNS, `slowdns`/`slowdnskey`, `active_load_balance_group_id` | Sin cambio de contenedor |
| Strings significativos `.so`: 2.142 en ambas, diff vacío | OK |
| Símbolos JNI: decrypt/encrypt +0x20, environmentFlags/lockMode +0x90 | Deriva de compilación |
| **dex_compare.py** | **NO FORMAT CHANGE** |

### 4. Cableado del servidor (head remoto 3e4a02c0)

| Comprobación | Resultado |
|---|---|
| `supplied-integrations.json` `/apps[29]`: oneftunnel, 127, `1ftnl`, prefijos, USER_PROFILES_ONLY | OK |
| `text-formats.json`: prefijos 1FTunnel registrados | OK |
| Gateway `c3-gateway.mjs`: formato `1ftnl` y prefijos enrutados | OK |
| `manifest.json`: entrypoint `1FTunnel.py`, payloadVersions 1–6 | OK |
| `codec.py` (worker): `range(1, 7)` + SlowDNS tras la corrección (§5) | **CORREGIDO** (antes: `range(1, 6)`, causa raíz del servidor) |
| `1FTunnel.py` (CLI): `range(1, 7)` — acepta v6 | OK |
| `1FTunnel_archivos.py`: usa `1FTunnel.decode` (acepta v6) | OK (rama binaria no afectada) |

## Lo que NO se probó

- Prueba en vivo contra el servidor desplegado (requiere auth de dispositivo
  y el redespliegue del worker con la corrección; pendiente).
- Re-ejecución del oráculo Unicorn sobre la `.so` 0.7.3 (fija el hash de la
  `.so` 0.6.99 y direcciones fijas; la autenticación GCM del archivo real
  0.7.3 con la clave 0.7.1 es prueba más fuerte).
- Descompilación completa del DEX (sin JADX/apktool en esta VM); la
  comparación se hizo sobre clases no ofuscadas, enums y tokens.
