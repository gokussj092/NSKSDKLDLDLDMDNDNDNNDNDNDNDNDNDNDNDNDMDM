# RESULTS — TSC VPN Proxy 6.4.3 (versionCode 6)

Fecha de las pruebas: 2026-11-14/15. Entorno: Python 3.12.3 del sistema, solo stdlib, sin red
para los tests de este expediente. Las pruebas en vivo citadas se hicieron 2026-11-14/15 con
los scripts operativos (ver `~/workspace/catalogs/tscvpn/` y NOTES.md).

## 1. Estado probado por via

| Via | Estado | Evidencia |
|---|---|---|
| catalog | VERIFIED | Worker en vivo type=full v1.0.93: 17 servidores (17 online), 671 tweaks (187 con payload, 429 con SNI), 1816/1816 valores enc: abren. type=servers: mismos 17 sin tweaks/settings. |
| files | PARTIAL | Sin formato propio exportable. cached_cloud_bundle.json / servers.json / tweaks.json / settings.json y valores enc: sueltos abren con el script de archivos; sin cached_cloud_bundle.json REAL de un telefono (formato verificado contra la respuesta en vivo, misma estructura por codigo). |
| text | NOT_APPLICABLE | Sin esquema propio ni deep link. Importacion por pegado de enlaces V2Ray estandar (vmess://, vless://, trojan://, ss://, socks://, hy2://, hysteria2://, tuic://, wireguard://), ya cubiertos genericamente por SP-DECODE. |
| export | PENDING | Cloud share (subir/descargar config por codigo) + registro de dispositivo + creditos: no verificado en vivo; necesita dispositivo registrado. |

## 2. Verificacion en vivo (oraculo independiente)

Catalogo en vivo (2026-11-14, re-verificado por coordinador): type=full v1.0.93, 17/671, 1816/1816 valores enc:; type=servers 17/0.

Self-tests de los scripts operativos: Catalogo 10/10, archivos 8/8 (scripts operativos, 2026-11-14; re-verificado por coordinador).

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

- Sin cached_cloud_bundle.json REAL de un telefono: el formato del cache se deduce del codigo (misma estructura que la respuesta en vivo).
- Cloud share sin verificar en vivo: requiere dispositivo registrado + creditos.
- Sin enlace real pegado en la app para confirmar el parseo v2rayNG con sus servidores.
- El worker sirve catalogo 1.0.93 aunque el APK trae 1.2.1 incluida; re-verificar cuando cambie la version servida.
- La clave de formato es fija en libisvcrypto.so; si el vendor la rota en una version nueva, el metodo deja de abrir.
- ¿Cuando servira el worker una version de catalogo nueva (hoy 1.0.93 frente a 1.2.1 incluida)?
- Flujo cloud share completo (registro de dispositivo + creditos).
