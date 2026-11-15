# RESULTS — Royal Tunnel VPN 7.0 (versionCode 7)

Fecha de las pruebas: 2026-11-14/15. Entorno: Python 3.12.3 del sistema, solo stdlib, sin red
para los tests de este expediente. Las pruebas en vivo citadas se hicieron 2026-11-14/15 con
los scripts operativos (ver `~/workspace/catalogs/royaltunnel/` y NOTES.md).

## 1. Estado probado por via

| Via | Estado | Evidencia |
|---|---|---|
| catalog | VERIFIED | En vivo v5.43: 29 servidores (V2Ray 14, UDP 4, WireGuard 3, SSH 3, DNS 3, OpenVPN 2), 105 tweaks (19 con Payload, 10 con SNI, 3 con v2rayjson), 0 errores de campo. Respaldo v5.17: 27 servidores, 100 tweaks. |
| files | VERIFIED_SYNTHETIC | .ROY: metodo completo por codigo (ExportActivity.n / RoyalTunnelMain.R) y muestra SINTETICA sample.roy (2648 B) generada desde el catalogo real; sin .ROY REAL exportado por la app. Controles observados: ExpireDate, RootBlock, DeviceID, PSInstall, isPassON/MyPass en texto plano. |
| text | NOT_APPLICABLE | Sin esquema de texto propio documentado para importar perfiles; la importacion es por archivo .ROY o por clave de nube. |
| export | PARTIAL | Nube por clave: Firebase Storage, ruta Roy://<20 caracteres [0-9a-z]>.roy; flujo descrito por codigo, sin clave real probada en vivo. |

## 2. Verificacion en vivo (oraculo independiente)

Catalogo en vivo (2026-11-14): v5.43, 29 servidores, 105 tweaks, 0 errores de campo; respaldo v5.17, 27/100.

Self-tests de los scripts operativos: Catalogo 15/15, archivos 18/18 (scripts operativos, 2026-11-14).

## 3. Tests de este expediente (sinteticos, sin red)

- `python3 tests/test_method.py` (unittest): **8 tests, OK** (exit 0).
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

- Sin .ROY REAL exportado por la app: el extremo a extremo con un perfil real sigue pendiente (nombres exactos de campos del perfil).
- Los Jdecrypt/Fdecrypt nativos de libwg-pro.so (AES-CBC/CFB) NO los usa el catalogo: sin llamadores Java y fallan sobre campos reales (codigo muerto o solo nativo).
- El actualizador de GitHub dice latest_version_code 6 (la app es 7); el endpoint actualizador no hace nada para este paquete.
- Modos NoobCrypt 2 (ChaCha20) y 3 (ChaCha20-Poly1305) implementados por completitud: la app los define pero ningun campo .ROY observado los usa.
- Nombres exactos de campos de un perfil .ROY real (vs. la muestra sintetica).
- ¿Alguna vez usa la app los modos NoobCrypt 2 y 3 en perfiles reales?
