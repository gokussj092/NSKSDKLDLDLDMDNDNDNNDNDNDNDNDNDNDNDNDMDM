# RESULTS — UT Loop Pro VPN 23.11.26 (versionCode 66)

Fecha de las pruebas: 2026-11-14/15. Entorno: Python 3.12.3 del sistema, solo stdlib, sin red
para los tests de este expediente. Las pruebas en vivo citadas se hicieron 2026-11-14/15 con
los scripts operativos (ver `~/workspace/catalogs/utloop/` y NOTES.md).

## 1. Estado probado por via

| Via | Estado | Evidencia |
|---|---|---|
| catalog | PENDING | BLOQUEADO por tokens de dispositivo (honesto): POST /v1/premium/config sin JWT -> 403 not_entitled; GET /v1/ota/config y /v1/ota/locked sin token OTA -> 401 access_required. Hacen falta el JWT de entitlement (compra) o un token OTA de Play Integrity de un dispositivo real con la app de Play. No se fabrico ningun token. Reserva incrustada (Version 1.0, 1 servidor + 1 tweak de ejemplo) SI abre con la clave de formato. |
| files | PARTIAL | Sin formato propio exportable. system.db (SQLite, tabla stored_data, fila ID=1, columna DATA = campo data del sobre OTA) SE ABRE OFFLINE. prem.cache / lock.cache estan sellados con clave del Android Keystore del dispositivo (alias utloop_premium_cache_v1 / utloop_locked_cache_v1): NO ABREN OFFLINE (KEYSTORE_SEALED). |
| text | NOT_APPLICABLE | Solo utloop://premium (abre Premium). Sin esquema de importacion ni file picker. Importacion por pegado de enlaces V2Ray estandar, ya cubiertos genericamente. |
| export | PENDING | Sin share por codigo; la 'nube' es el API premium/OTA/locked + Firebase Messaging. Sincronizacion por version (PremiumRev / LockedRev / Version). |

## 2. Verificacion en vivo (oraculo independiente)

Sondeo en vivo (2026-11-14): nonce 200; premium 403 not_entitled; ota/locked 401 access_required. Reserva incrustada abre (v1.0, 1/1).

Self-tests de los scripts operativos: Catalogo 13/13, archivos 7/7 (scripts operativos, 2026-11-14).

## 3. Tests de este expediente (sinteticos, sin red)

- `python3 tests/test_method.py` (unittest): **7 tests, OK** (exit 0).
- `python3 tools/verify.py`: **OK** (exit 0).
- Fixtures en `tests/fixtures/`: vectores SINTETICOS generados con claves TEST-ONLY
  (`bytes(range(...))`); no contienen material real, servidores reales con claves ni perfiles reales.
- pytest NO esta instalado en este entorno; los tests son `unittest` (stdlib) y compatibles
  en forma con pytest cuando este instalado.

Clasificacion: lo anterior es **VERIFIED_SYNTHETIC** para la logica del formato.
Lo en vivo es **VERIFIED_REAL** solo donde la via lo indica arriba; donde la via es
PENDING/FAILED, nada sintetico la convierte en verificada.

## 4. Pruebas negativas (incluidas en tests/test_method.py)

- Entrada truncada -> `ValueError`.
- Base64 invalido / HTML inesperado -> `ValueError`.
- Ciphertext/tag alterado -> `ValueError` (tag GCM / padding / palabra de longitud).
- Prefijo / firma ausente o incorrecta -> `ValueError` / `False` segun la via (ver el test).

## 5. Limites y pendientes

- Catalogo en vivo BLOQUEADO: sin JWT de entitlement ni token OTA de Play Integrity no hay catalogo real.
- prem.cache / lock.cache no abren offline: clave en Android Keystore del dispositivo (no exportable).
- La app tiene lista anti-sniffing (HttpCanary, Packet Capture, Reqable, etc.).
- jadx murio al 58%; todo com/utloop esta decompilado pero el resto es parcial.
- ¿Como obtener un JWT de entitlement o un token OTA legitimo? (requiere dispositivo real + compra / Play Integrity).
- Contenido real del catalogo vivo (Version, servidores, tweaks).
