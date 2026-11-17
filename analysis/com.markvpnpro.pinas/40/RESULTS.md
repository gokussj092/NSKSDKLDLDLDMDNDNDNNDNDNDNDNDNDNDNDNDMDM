# RESULTS — ANY VPN build 40 (versionCode 40)

Fecha de las pruebas: 2026-11-17. Entorno: Python 3.12.3 del sistema; PyCryptodome 3.23.0
(para el codec y los tests) y `requests` 2.33.1 (solo el script de investigación).

## 1. Estado probado por via

| Via | Estado | Evidencia |
|---|---|---|
| catalog | VERIFIED | Catálogo remoto en vivo v7.3: 13 servidores, 89 redes, descifrado completo (0 campos sin descifrar, 0 caracteres CJK restantes). |
| files (.dtk) | VERIFIED_SYNTHETIC | Contenedor sellado AES con secciones server/network como cadenas JSON; vectores reales del catálogo (host/usuario) + roundtrip sintético con valores sustituidos CJK. Sin .dtk REAL exportado por la app. |
| text | NOT_APPLICABLE | Sin esquema propio; enlaces v2ray estándar por portapapeles, ya cubiertos por SP-DECODE. |
| export | NOT_APPLICABLE | Sin cloud de perfiles por token identificada. |

## 2. Verificación en vivo (oráculo independiente)

- `ANY_VPN.py --self-test`: **8/8 PASS** (incluye descarga en vivo:
  `live fetch+decrypt | Version=7.3 Servers=13 Networks=89` y `no download APIs in output`).
- `ANY_VPN.py --out live.json` (re-corrida fresca): **byte por byte idéntica** a
  `~/workspace/catalogs/anyvpn/live.json` (SHA-256 `8e619516d83ed5c484714d03ec94fedead37c4e741d41a5b2b0a70c600b78cfe`).
- Cuerpo crudo en vivo: 115820 B, SHA-256 `ad4bc4b7c0e482caebff603390262c03d4808b03b7558f44c99c3f33da6ecc49`.
- Codec ANTERIOR del repo sobre el mismo cuerpo v7.3: decodifica el sobre (Version 7.3,
  13 servidores, 89 redes) pero devuelve los valores de campo en CJK
  (`ServerIPHost` = `く듌.山大.듌.大く땀`, `ServerUser` = `su国的为딸땬`,
  `config_url`/`account_api` también en CJK y PRESENTES en el resultado).
- Codec NUEVO del staging sobre el mismo cuerpo (guardado y descarga fresca):
  **dict idéntico a `live.json`**, 0 caracteres CJK restantes,
  `config_url`/`account_api` ausentes. Host de muestra: `45.81.5.149`, usuario `sumonbd`.
- `.dtk` sintético con campos sustituidos CJK → `decode_profile()`: host `45.81.5.149`,
  usuario `sumonbd`, SNI `example.invalid` (roundtrip OK).
- `ANY_VPN_archivos.py --self-test`: **8/8 PASS** (incluye vector real del catálogo
  y enlace `vless://` real).
- Tests del repo `tests/test_any_vpn.py` contra el codec nuevo: **12/13 OK, 1 skipped**
  (oráculo JDK, sin Java en este entorno). El único fallo es el esperado:
  `test_complete_catalog_preserves_names_plain_certificates_and_flags` espera
  `config_url`/`account_api` en la salida; el codec nuevo los elimina por la regla
  del catálogo (ver spec en REPORT.md).
- `py_compile` del codec nuevo, `MinaProNet.py` y `MinaProNet_archivos.py`: OK (3/3).

## 3. Tests de este expediente (sintéticos, sin red)

- `python3 tests/test_method.py` (unittest): **6 tests, OK** (exit 0).
  Requiere PyCryptodome (el codec la usa en runtime; el worker la tiene fijada en 3.23.0).
- Fixture en `tests/fixtures/synthetic_catalog.json`: catálogo SINTÉTICO esperado
  (hosts 203.0.113.x, TEST-NET; usuarios `testuser`/`testpass`); sin datos reales.

Clasificación: lo anterior es **VERIFIED_SYNTHETIC** para la lógica del formato.
Lo en vivo es **VERIFIED_REAL** solo donde la vía lo indica arriba.

## 4. Pruebas negativas (incluidas en tests/test_method.py)

- Campo cifrado inválido (`not encrypted`, booleano, base64 corto) → `DecodeError`.
- Sobre no-JSON / no-base64 / vacío / sobre-límite → `DecodeError`.
- Padding corrupto (último byte alterado) → `DecodeError`.
- Estructura duplicada / vacía / no finita / profundidad > 64 → `DecodeError`.

## 5. Límites y pendientes

- Sin archivo `.dtk` REAL exportado por la app.
- El catálogo en vivo no se probó dentro de la app instalada (sin teléfono).
- `freeze.php` 404 (registro de servidor gratis eliminado); `auth.php` responde
  `{"auth":false,...}` sin parámetros; `c_11.data_url` devuelve HTML, no catálogo.
  Ninguno afecta al catálogo.
- El endpoint `https://abc.dnsbd.top/api/auth.php` es inalcanzable desde esta VM
  (error del proxy de salida); no está probado que esté caído.
- Kill-switch de Pastebin vivo (200): `com.markvpnpro.pinas` NO está en la lista.
