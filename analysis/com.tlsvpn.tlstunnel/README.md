# TLS Tunnel — com.tlsvpn.tlstunnel

Matriz de builds y hallazgos (expediente por build, según la política de
evidencias).

| Build | Versión | Estado | Hallazgo |
|---|---|---|---|
| [516](516/) | 8.5.0 | VERIFIED_SYNTHETIC (puerto nativo); método Python VERIFIED_REAL en trabajo previo | Contenedor AES-256-GCM, 6 perfiles de clave fija. Decodificador nativo C++ offline + harness 13/13 MATCH vs oráculo. Falta muestra real `.tls` para VERIFIED_REAL del puerto nativo. |
| 518 | 8.5.2 (en vivo desde 2026-11-05) | PENDING | APK no descargable en la VM (espejos 403/000). Changelog: solo "Lib updates". Falta confirmar que los 6 perfiles siguen vigentes. |

Sin muestra real `.tls` en el repo (la muestra real 8.5.0 del trabajo previo
es privada; solo su SHA-256 está registrado en `tests/test_tls_decoder.py`).
