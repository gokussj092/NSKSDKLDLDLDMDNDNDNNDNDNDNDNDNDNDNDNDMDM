# Mx Tunnel PRO — Mx-Build48

Paquete `com.mxtunnel.pro`, código 48. Lector del catálogo completo, integrado
como proveedor Cloud `mx-tunnel-pro`. Python 3.10+; biblioteca estándar.
Conservar `codec.py` y la dependencia hermana
`../HX_Tunnel_VPN/HX_Tunnel_VPN.py` al copiar fuera del repositorio.
No requiere APK, bibliotecas nativas ni Android para ejecutarse.

```bash
python server_catalog_decoder.py --download > catalogo.json
python server_catalog_decoder.py copia-cifrada.json > catalogo.json
python server_catalog_decoder.py --stdin < copia-cifrada.json > catalogo.json
```

Sin argumentos descarga la misma fuente fija. `run(data: bytes) -> str` es
estrictamente offline. stdout recibe el JSON completo y stderr un error genérico
con código 1. Entrada/salida limitadas a 8 MiB; no hay límite por número de registros.

La URL recuperada del APK es
`https://rasedpanel.xyz/updater/750b71355b025b19884ee835b759d6`.
La descarga valida TLS, usa timeout, rechaza redirecciones, HTML y respuestas
excesivas. El broker Cloud conserva sus controles de DNS/IP y límites generales.

`Dm.<clinit>` contiene la clave de formato `...|...`, recuperada mediante
LSParanoid. `Dm.b/d` usa XXTEA con delta propio `-1638454863` / `0x9e5729b1`,
palabras little-endian, clave truncada/rellenada a 16 bytes y tráiler de longitud.
`DJ.e` elimina espacios/saltos del Base64 y llama a `Dm.c`, después lee el JSON.
Es la misma primitiva histórica HX/TRV/4U con otra clave: se reutiliza el motor
compartido mediante un argumento keyword-only, conservando su clave por defecto.
No se modifica el estado global del lector compartido.

Se conservan todos los campos y tipos: `Version`, `Username`, `Password`,
`Changelogs`, `Free_servers`, `Premium_servers`, `Vip_servers`, `Private_servers`,
`Payloads`, registros duplicados, valores vacíos y metadatos desconocidos. Los
campos internos del catálogo confirmado se leen directamente como JSON; no se
aplican filtros de la interfaz ni se incorporan tweaks privados del teléfono.

Descarga real autorizada del **2026-10-22**: HTTP 200, versión **564**,
**39 servidores y 1467 payloads**. Asset `assets/gremlin.json`: versión **497**,
**51 servidores y 1396 payloads**. Ambos documentos completos coinciden con JDK
independiente, CLI y worker aislado, sin salida parcial. Son recuentos observados,
no límites permanentes. Los grupos Premium/Vip/Private vacíos se conservan.

El icono es el PNG original exacto de `res/drawable/ic_app_icon.png`, 512×512.
No se registra un formato de archivo exportado sin muestra validada. El material
interno Psiphon `server.psi` no se presenta como catálogo adicional de usuarios.
No se certifican sesiones VPN, ejecución Android, despliegue VPS o CI remota.
Ver [TESTING.md](TESTING.md) y [manifest.json](manifest.json).
