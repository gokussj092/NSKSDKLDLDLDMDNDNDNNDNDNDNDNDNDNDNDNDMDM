# Resultados — Genis VPN 2.2.6 / build 76

**VERIFIED_REAL para catálogo remoto; transporte Node/VPS pendiente, sin despliegue.**

| Entrada real | Versión | Perfiles | Campos CBC no vacíos | Campos vacíos | JCA / CLI / worker completos |
| --- | --- | --- | --- | --- | --- |
| Catálogo remoto, HTTP 200 | 1114 | 84 servidores | 658 | 241 | Iguales |
| Configuración incluida | 1 | 1 servidor | 8 | 3 | Iguales |
| Usuarios incluidos | 1 | 1 usuario | 7 | 0 | Iguales; no se anuncia descarga remota |

El JSON remoto tiene 61319 bytes y SHA256 `6d7d7b318a443292450af15e640714a848fd5db298d4fbafb73971974f49e56b`. Se conserva privado, fuera de Git. No se reemplaza la descarga remota por ninguno de los incluidos.

Suite actual: **9 Python + 161 Node, todas aprobadas**. Incluye vectores JCA ficticios, CLI, worker aislado, metadatos completos, campos nuevos, vacíos, errores de Base64/HTML/truncado, claves duplicadas, tipos inválidos, redirecciones, DNS privado, switches y gateway autenticado. El test HTTP de gateway usa bytes/JSON ficticios y red simulada; no acredita conectividad real.

Python operativo descargó y descifró el documento real. Node real: `REMOTE_NETWORK_DENIED` en este ejecutor. Replay Node con bytes reales y resultado del worker real: `SIMULATED_HTTP_REAL_BYTES`, una petición, JSON completo igual. Debe repetirse el transporte Node real en VPS antes del rollout.

Catálogo Cloud: piso 69, 65 fichas, 256 formatos; versiones superiores configuradas y decisiones previas de operadores conservadas. Icono launcher original WEBP convertido a PNG sin cambiar sus píxeles. Constantes de formato inline en backend. No se editaron ni compilaron componentes Android, no hubo merge/deploy y no se certificó exportación unlocked.
