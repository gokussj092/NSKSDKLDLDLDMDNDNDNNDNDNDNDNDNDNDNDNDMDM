# RESULTS — PPH GOOD VPN 1.7.2 (versionCode 75)

Fecha de las pruebas: 2026-11-14/15. Entorno: Python 3.12.3 del sistema, solo stdlib, sin red
para los tests de este expediente. Las pruebas en vivo citadas se hicieron 2026-11-14/15 con
los scripts operativos (ver `~/workspace/catalogs/pph/` y NOTES.md).

## 1. Estado probado por via

| Via | Estado | Evidencia |
|---|---|---|
| catalog | VERIFIED | En vivo Version 6.6 ('pvpn_upall'): 15 servidores (5 UDP Hysteria + 5 OpenVPN/SSL + 5 SSH), 7 redes, las 7 con payload. 0 campos sin abrir tras la limpieza 2026-11-15. Incluido (assets/pphdev.json): Version 2.0, 60 servidores, 14 redes, tambien 0 campos sin abrir. |
| files | VERIFIED | Sin formato propio exportable con extension. Se abre el catalogo crudo (una linea Base64, pphdev.json o el cuerpo descargado), el JSON ya descifrado, un campo suelto, y Parser.encode/decode. La app importa .ovpn estandar y enlaces v2ray genericos, ya cubiertos por SP-DECODE. |
| text | NOT_APPLICABLE | Sin esquema propio; la app maneja enlaces v2ray genericos por pegar (vmess://, vless://, trojan://, ss://), ya cubiertos genericamente. |
| export | NOT_APPLICABLE | Sin share por clave ni nube documentada para esta app. |

## 2. Verificacion en vivo (oraculo independiente)

Catalogo en vivo (2026-11-14, re-verificado 2026-11-15): v6.6, 15 servidores, 7 redes, 0 campos sin abrir; incluido v2.0, 60/14, 0 sin abrir.

Self-tests de los scripts operativos: Catalogo 25/25, archivos 17/17 tras la limpieza 2026-11-15 (antes 10/10 y 14 checks).

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

- La app guarda Servers/HTTPNetworks en su SQLite (tabla Harlies_table); el catalogo NO se guarda como archivo.
- Los campos cortos en claro (TcpPort, ProxyPort, FLAG, etc.) no se descifran a proposito (falsos positivos Base64+XXTEA).
- jadx 1.5.3: primera pasada OOM al 61%; segunda con -j 2 -Xmx3500m OOM al 99% (10212 archivos .java, 30 errores menores); todas las clases clave decompiladas.
- Ninguno abierto: catalogo vivo e incluido verificados con 0 campos sin abrir.
