# Validación de V2ray Tunnel Plus 10.0.0

Validado el **2026-10-22**. Paquete `vpn.v2raytunnelplus.com.eg`, build 4000010.
APK base SHA-256:
`b05ed5cf21b9741fe25a80383782533feb0673f4350c88191f1f8112591e5888`.

## Documentos reales completos

Descargas autorizadas por el usuario, HTTP 200 sin redirección:

| Fuente inicial | Bytes | Perfiles | Comparación completa Java/Python |
| --- | --- | --- | --- |
| V2RAY_BASE64.txt | 49052 | 150 | Igual |
| V2RAY_RAW.txt | 36788 | 150 | Igual |

Base64 SHA-256: `6627d9c40a45a9c8e8e33fce733969f982c932196ba1a68f76900c16ef79f4d3`.
Texto SHA-256: `a2bae8af49c853153e358ad10cd0b9afa1f635e6bee790aa2fc2e2fae37c116a`.
Al abrir Base64 se obtienen exactamente los bytes del texto: la misma lista de
150 perfiles, 68 VLESS / 39 VMess / 24 Shadowsocks / 19 Trojan. Los recuentos
son observaciones, sin un límite fijo por cantidad de servidores.

`tests/golden/v2ray_tunnel_plus_oracle.java` utiliza Base64, URI y URLDecoder
del JDK, independiente del parser Python y basado en los lectores del APK.
Se compararon todos los URI y campos, el texto íntegro, las líneas y el JSON
completo de ambas fuentes. VMess JSON conserva su documento original completo.

La CLI real `--all` volvió a descargar ambas fuentes. El proveedor actualizó
los bytes durante la validación; se capturaron las respuestas de esa misma
ejecución y se compararon de nuevo contra Java, íntegramente: 150 perfiles
por fuente y texto decodificado idéntico entre ellas. No se exige igualdad
entre capturas tomadas en distintos momentos.

También pasó el paquete real completo en el worker aislado. Flujo autenticado
local verificado: petición → broker con capturas reales de ambas fuentes fijas
→ worker HTTP privado real → proceso aislado → resultado completo igual al
oracle, `isPartial:false`. El DNS externo nativo Node devuelve `EAI_AGAIN`;
DNS/IP/TLS/redirecciones se comprueban con transporte controlado y las descargas
externas reales se realizaron por Python/HTTPS. No se afirma despliegue ni
conectividad externa desde la VPS. No se establecieron sesiones VPN.

## Pruebas reproducibles

Con dependencias del repositorio instaladas en el mismo Python que usan los
procesos aislados y con JDK disponible:

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_v2ray_tunnel_plus tests.test_tunelguard tests.test_http_wakko tests.test_http_socketclay tests.test_http_fenixvpn tests.test_http_jireh tests.test_cloud_c8_android_server_vpn -v
python scripts/cloud_c0_inventory.py --check
cd cloud/web
npm test
```

**89 pruebas Python aprobadas**, incluidas **11 de esta app**, y **173 pruebas
Node aprobadas**. Inventario C0 intacto y `git diff --check` correcto. No se
presupone el resultado de CI remota.

Vectores públicos enteramente sintéticos: 12 registros, los ocho esquemas,
VMess JSON/URI, Shadowsocks legado/SIP002, SOCKS con/sin autenticación,
IPv6, espacios y `|`, Unicode y doble escape de fragmento, parámetros
repetidos/desconocidos/vacíos y JSON anidado con tipos originales.
Pruebas de 1000 registros idénticos verifican ausencia de truncación y
deduplicación. Se rechazan último registro inválido, protocolo desconocido,
URI/puerto/Base64 corruptos, JSON duplicado/no finito/profundo, paquetes con
fuentes ausentes/intercambiadas, HTML/redirecciones/compresión y límites.
Se cubren CLI fuera del repositorio, proceso aislado, fallo de una fuente,
paridad rawText/structuredJson, controles administrativos, versión e icono exacto.

## Entrega

- `decoders/Python/apps/V2ray_Tunnel_Plus/`: lector, codec, dependencias,
  manifiesto, README, TESTING e icono PNG original.
- `tests/test_v2ray_tunnel_plus.py`, oracle Java y vectores sintéticos;
  suite incluida en CI C2.
- Worker: `catalog_vpn_bridge.py` y allowlist de `engine.py`.
- Backend: proveedor fijo, broker, validación C3 y paquete dual generalizado,
  manteniendo los paquetes anteriores de SocketClay/Wakko.
- Catálogo público 18, icono, control administrativo y pruebas web; índice de
  apps y registro `docs/cloud/NUEVAS_INTEGRACIONES_VPN.md` actualizados.

No se añade formato de archivo propietario, detector Android o writer.
No se ejecutó Android ni se certificó la disponibilidad de servidores VPN.
Los datos reales y APK quedan fuera de Git y CI.
