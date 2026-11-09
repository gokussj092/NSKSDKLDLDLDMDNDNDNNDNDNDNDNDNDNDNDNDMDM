# Resultados — Tunneltweak build53

Estado del catálogo: VERIFIED_REAL. Se verificó com.tunneltweak.loyalteams, 6.2.3 / versionCode53. Hashes de XAPK, APK y certificado extraído en generated/identity.json; no se ejecutó la APK.

| Evidencia real | Resultado |
| --- | --- |
| Solicitud anterior x-app-version51 | HTTP426, update_required, minVersionCode53 |
| Solicitud coherente con build53 | HTTP200, 23789 bytes |
| Catálogo completo | 2 servidores y 68 configuraciones |
| Oráculo Java/JCA reutilizado | Igualdad íntegra con Python |
| Worker aislado real | structuredJson y rawText íntegros, isPartial=false |
| Salida renderizada | 25362 bytes; metadatos exteriores conservados |

El cambio necesario es el encabezado del build real. PBKDF2-HMAC-SHA25610000 y AES-GCM se mantienen; el oráculo existente se reutilizó sin modificaciones. No se emplearon credenciales de suscripción. generated/catalog-proof.json conserva los hashes, conteos y banderas de paridad; no se sube el catálogo claro ni cifrado.

## Pruebas

17 tests específicos de Tunneltweak correctos; junto con Wolf16/build13, 33 Python correctos. Se mantienen TTPBE1, CBC/XOR, rutas históricas, contraseña requerida, autenticación negativa, metadatos, tipos y campos desconocidos. 178 tests Node y 116 tests Python de consumidores de interfaces compartidas también correctos. Los fixtures son los golden sintéticos preexistentes, con hashes en dependencies.lock.json; no son exportaciones reales de teléfono.

## Herramientas y límites

Python3.12.14, Androguard4.1.3, JADX completo1.5.6, JDK21.0.13, PyCryptodome3.23.0, Node24.22.1 local y Node22 en CI. Se reutilizan sin cambios el descargador TunnelDoom, instalador JADX, tunneltweak_oracle.java y tunneltweak_vectors.json; se documentan hashes/versiones y dependencias transitivas en DEPENDENCIES.md y dependencies.lock.json. tools/ conserva todos los wrappers propios de adquisición, análisis, solicitud y validación.

JADX terminó con errores en métodos ajenos a las clases comprobadas; no se declara descompilación global completa. El broker Node local recibió REMOTE_NETWORK_DENIED por la salida de red del entorno; la descarga Python y el worker real sí se comprobaron, sin modificar los controles de red. El workflow de descargas comprobará el broker desde GitHub.

No se verificó criptográficamente la firma completa del APK, una sesión Android/VPN ni una exportación real independiente del teléfono. No se compiló APK ni se desplegó VPS. No se otorga aprobación automática a herramientas nuevas; las licencias desconocidas siguen pendientes de revisión.

## Auditoría de metadatos e impacto

A0 sin hallazgos bloqueantes; P06 PASS_WITH_UNRESOLVED: 7 fuentes de método modificadas, 99 fuentes alcanzadas, 13 expedientes afectados y 56 consumidores sin resolución estática. Los nueve expedientes consumidores existentes incorporan revisión documental; estos resultados no aprueban herramientas ni validan catálogos adicionales.
