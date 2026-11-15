# Resultados — Wolf Custom VPN build16

Estado del catálogo: VERIFIED_REAL. Identidad real v1.11.06.1 / core.vpn3jx.xtreme / versionCode16; adquisición y análisis estático reproducibles en REPRODUCE.md. APK y biblioteca nativa no ejecutados.

| Evidencia real | Resultado completo |
| --- | --- |
| Fuente anterior | HTTP404; ya no es el actualizador de build16 |
| Nuevo POST público | HTTP200, 2534153 bytes, catálogo v1.09 |
| Catálogo remoto | 41 servidores, 1851 redes, 902 campos cifrados comparados |
| Catálogo incluido | v1.01, 24 servidores, 1851 redes, 252 campos comparados |
| Oráculo propio Go independiente | Igualdad del JSON completo remoto e incluido con Python |
| Worker aislado real | structuredJson y rawText completos, isPartial=false, igualdad remota con el oráculo |
| Salida remota | 2212399 bytes; dentro del límite existente de 4MiB y tiempo de 120s |

Los SHA-256, tiempos y conteos están en generated/catalog-proof.json y generated/embedded-proof.json. El JSON claro completo se mantuvo fuera de Git. La repetición final tras el tratamiento de UTF-8 autenticado mantuvo el mismo hash y los mismos conteos; worker 20.419s, decodificador 15.916s. Son medidas de este entorno, no garantía de latencia VPS.

## Pruebas reproducibles y compatibilidad

- 33 tests Python entre tests.test_wolf_v16 (7), tests.test_wolf_custom_vpn (9) y tests.test_tunneltweak (17), todos correctos.
- 178 tests Node del broker/catálogo y consumidores: 62 directos y 116 de regresión de versión mínima, todos correctos.
- 116 tests Python adicionales de consumidores de las interfaces compartidas: 75 existentes más 9 DoriaX VIP, 10 Netfree, 11 XXPICORE y 11 Dastan, todos correctos. No validan descargas de esos otros proveedores.
- Se conservan build13, .wolf histórico y .wolftunnel, claves desconocidas, tipos, listas y metadatos. ultra.py permanece sin cambios.
- Vectores propios sintéticos generados por Go, positivos y negativos (salt/nonce/cipher/tag corruptos, Base64/letra inválidos, documento incompatible y UTF-8 inválido autenticado sin fallback). No contienen datos del catálogo real.

Fixture build16 SHA-256: 6ec234c7b4b79e17ad011636d9269bc566a8a51d42605cbf8e8ace9f6ce3e08a. La generación conserva 10 sobres/campos sintéticos; fixtures no certifican exportación de un teléfono real.

## Herramientas efectivamente ejecutadas

Python3.12.14, PyCryptodome3.23.0, argon2-cffi25.1.0, Androguard4.1.3, pyelftools0.32, Capstone5.0.6; JADX completo1.5.6 sobre JDK21.0.13; Go1.27.3 y x/crypto0.36.0; Node24.22.1 local (Node22 en CI). Versiones, licencias conocidas, hashes y transitivas en DEPENDENCIES.md y dependencies.lock.json.

Se reutilizaron sin editar el adquisidor de TunnelDoom, instalador JADX, resolver LSParanoid y oráculos/build13; se conservaron sus hashes. Los lectores ARM64 previos se consultaron; la adaptación ARM32 y el oráculo Go son nuevos y están en tools/. Fallos de adquisición/API, descarga JADX504 y decompilación parcial constan en ANALYSIS.md.

## Límites

El broker Node local rechazó la salida de red del entorno con REMOTE_NETWORK_DENIED; no se desactivó la protección de red. La descarga real y la paridad se comprobaron con las herramientas Python; el workflow global de descargas verifica el broker en GitHub. Los resultados remotos de CI se documentarán por enlace, sin confundirlos con estas pruebas locales.

La firma criptográfica íntegra del APK, una sesión Android, conexión VPN, exportación real independiente .wolf y rendimiento VPS no están certificados. No se compiló APK ni se desplegó al servidor. Las herramientas nuevas no se incorporan al ejecutor automático de análisis ni reciben aprobación automática; las licencias desconocidas siguen pendientes de revisión.

## Auditoría de metadatos e impacto

A0 sin hallazgos bloqueantes; P06 PASS_WITH_UNRESOLVED: 7 fuentes de método modificadas, 99 fuentes alcanzadas, 13 expedientes afectados y 56 consumidores sin resolución estática. Los nueve expedientes consumidores existentes incorporan revisión documental; estos resultados no aprueban herramientas ni validan catálogos adicionales.
