# RESULTS — TCx Tunnel Plus 1.0.15 (versionCode 115)

Fecha de las pruebas: 2026-11-14/15. Entorno: Python 3.12.3 del sistema, solo stdlib, sin red
para los tests de este expediente. Las pruebas en vivo citadas se hicieron 2026-11-14/15 con
los scripts operativos (ver `~/workspace/catalogs/tcx/` y NOTES.md).

## 1. Estado probado por via

| Via | Estado | Evidencia |
|---|---|---|
| catalog | FAILED | MUERTO: HTTP 404 (14 B) en vivo, re-verificado; el repo GitHub del desarrollador esta eliminado. Solo vuelve si el desarrollador lo republica o aparece un classes5.dex/a.rlb de un telefono. |
| files | VERIFIED_SYNTHETIC | .tcx = texto tcxtunnelplus://<cifrado modo 0> del JSON de perfil. Muestra SINTETICA sample.tcx abre con el script de archivos y con renz_decrypt nativo bajo Unicorn (devuelve el JSON exacto del perfil de prueba). custom_payload.json se escribe CIFRADO (modo 0 sin prefijo). Sin .tcx REAL ni custom_payload.json real del telefono. |
| text | VERIFIED_SYNTHETIC | tcxtunnelplus:// (pegado dentro de la app; sin intent-filter para el esquema en el manifest). La muestra sintetica abre; sin enlace real. |
| export | NOT_APPLICABLE | Sin share por clave ni nube documentada para esta app. |

## 2. Verificacion en vivo (oraculo independiente)

Catalogo en vivo MUERTO: HTTP 404 (14 B), re-verificado, exit 2. Vector sintetico y .tcx sintetico abren (este ultimo tambien con renz_decrypt nativo bajo Unicorn).

Self-tests de los scripts operativos: Ambos scripts --self-test OK (conteos no registrados en NOTES.md).

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

- Catalogo muerto: repo GitHub eliminado; sin fuente viva.
- Sin .tcx REAL ni custom_payload.json real del telefono (nombres exactos de campos del perfil pendientes de confirmar).
- La semilla se fija en runtime desde la firma del APK (getSignKey): el catalogo/.tcx solo abre en la app ORIGINAL firmada (anti-tamper).
- jadx: primera pasada murio al 56% (OOM); segunda solo sobre classes3.dex termino al 99% con 3 errores.
- ¿Republicara el desarrollador el catalogo (nuevo repo) o aparecera un classes5.dex/a.rlb con la fuente?
- Nombres exactos de campos de un perfil .tcx real.
