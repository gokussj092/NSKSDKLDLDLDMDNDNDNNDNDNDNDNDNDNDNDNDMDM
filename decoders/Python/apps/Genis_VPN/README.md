# Genis VPN — catálogo Cloud

Build analizado: `com.doriaxvip.tunnel` 2.2.6 / 76. Fuente remota real: versión 1114, 84 servidores, 658 campos CBC no vacíos. JSON completo comprobado contra JCA, CLI y worker aislado. El formato usa WakkoDev/MD5/AES-CBC y campos IV/AES-CBC/ROT22 Java; no tiene autenticación mediante tag.

El CLI descarga únicamente el updater fijo o abre un ciphertext por ruta/--stdin. Sus constantes de formato están inline y no requieren un .env nuevo. Usuarios incluidos v1 verificados aparte; no se anuncia su actualización remota ni se mezclan con los servidores remotos.

Expediente, scripts, dependencias, fixtures ficticios y límites: [analysis/com.doriaxvip.tunnel/76](../../../../analysis/com.doriaxvip.tunnel/76/ANALYSIS.md).

Integrado en la rama de Cloud con controles individuales e icono original. Transporte Node real en VPS y rollout pendientes; sin cambios Android ni exportación unlocked certificada.
