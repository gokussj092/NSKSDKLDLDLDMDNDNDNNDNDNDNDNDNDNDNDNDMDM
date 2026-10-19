# SP-DECODE Cloud — C0: auditoría y línea base de migración Android

**Estado:** fase C0 implementada como inventario, verificaciones estáticas y controles de regresión; **ningún motor ha sido migrado**.  
**Rama de trabajo:** `feat/cloud-c0-audit-baseline` (aislada de `main`).  
**Alcance:** solo SP-DECODE Android. El bot y sus motores originales se mantienen intactos.  
**Biblioteca C++ futura:** `libspdecode.so` (nombre acordado; **no creada en C0**).

## 1. Reglas innegociables

1. **UI/UX Android intacta.** Sin rediseño de pantallas, navegación, textos, temas, componentes o comportamiento de presentación. El proyecto fija nueve fuentes visuales con el hash de objeto Git de `main` en [C0_UI_BASELINE.json](C0_UI_BASELINE.json). `MainActivity.kt` se excluye de ese bloqueo por necesitar reemplazar la orquestación durante C4, **no** para permitir cambios visuales.
2. **Todo descifrado Android se ejecutará en el servidor.** No basta portar los 239 formatos nominales: se incluyen `.solid`, importadores, catálogos, protocolos de texto y versiones/variantes efectivamente compatibles.
3. **La API y su comunicación se integrarán mediante C++/JNI** en Android bajo el nombre `libspdecode.so`. El código nativo no es un almacén seguro: claves maestras, tokens de servicio permanentes y algoritmos propietarios viven en backend; un binario C++ puede inspeccionarse.
4. **Sin modificar el bot.** La API podrá reutilizar scripts originales por medio de workers aislados, sin importar las sesiones o controladores Telegram ni cambiar su resultado.
5. **Sin falsos positivos de compatibilidad.** La presencia de una ruta o un resultado sintético no equivale a una versión de exportador real certificada. No se retirarán decodificadores Android hasta aprobar pruebas de paridad.
6. **Sin datos sensibles en el inventario, commits ni CI.** No se copian llaves, tablas, ejemplos privados ni archivos de usuarios; los materiales de prueba serán sintéticos.

## 2. Resultado C0.1: inventario de archivos

Se ha congelado la matriz [C0_FORMAT_MATRIX.csv](C0_FORMAT_MATRIX.csv), obtenida del catálogo Android y cruzada con `spdecode.registry.DECODER_REGISTRY`.

| Fase previa Android | Rutas registradas | Base de ejecución original |
| --- | ---: | --- |
| legacy | 61 | Implementaciones específicas |
| B: generic | 81 | Motores genéricos por perfil |
| C: Ultra | 41 | Ultra/Sandok |
| D: RENZ | 16 | RENZ / 7NET |
| E: special | 27 | Familias especiales |
| F: independent | 13 | Motores independientes |
| **Subtotal Android** | **239** | **228 Python, 8 Node.js y 3 PHP** |
| NUR `.solid` adicional | 1 | Python |
| **Total de rutas de archivos auditadas** | **240** | **77 scripts originales distintos** |

**Precisión:** las 239 entradas registradas figuran con puertos Android presentes, **cero** certificaciones Android de versiones de exportador en el catálogo, y 238 indicadores de cobertura sintética Linux. El corpus A.2.3 independiente contiene **60 casos golden para 59 sufijos originales**, no 239 ensayos reales en Android. `.solid` está fuera de la numeración histórica 239.

Las rutas compuestas se detectan por el sufijo más largo (ej. `.sksrv.png`). El formato `.ost` conserva su prioridad histórica antes del fallback Ultra. `.hc` tiene varias vías (tradicional/HCCFG y requisitos de contraseña/HWID). Estos comportamientos son parte de la futura batería de paridad.

**Fuentes comprobadas:**

- `android/app/src/main/assets/decoder_catalog.json` (esquema 3).
- `scripts/android_a24_catalog.py` y `spdecode/registry.py`.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/parity/AndroidDecoderCatalog.kt`.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/parity/AndroidOfflineDecoderRouter.kt`.
- `decoders.json` y rutas originales `decoders/Python/`, `decoders/JavaScript/`, `decoders/PHP/` cuando correspondan.

## 3. Resultado C0.2/C0.3: superficies que no caben en el CSV de extensiones

| Superficie Android | Punto de entrada actual | Exigencia futura |
| --- | --- | --- |
| Archivos normales y lotes | `MainActivity.kt` → `AndroidOfflineDecoderRouter` | Enviar archivo y nombre de formato a API; conservar rawText y resultados |
| Archivos HCCFG protegidos | `HcHccfgPort.kt`, `HcProtectedImportDialog.kt` | Mantener negociación contraseña/HWID y variantes; nunca registrar credenciales |
| `.solid` NUR Tunnel | `AndroidDecoderCatalog.detect`, `NurTunnelPort` | Endpoint de archivo separado del catálogo NUR |
| Catálogo de servidores NUR | `NurTunnelServerCatalog.kt` | Recuperación controlada + procesamiento del catálogo en backend |
| Textos y enlaces tradicionales | `TextProtocolDecoder.kt` | Reproducir detección, normalización, protocolos y resultado JSON |
| Textos adicionales Phase G | `TextPhaseGPort.kt` | Conservar alias, Base64, RENZ, XOR, NPVS y errores diferenciados |
| HTTP Injector Cloud | `HttpInjectorCloudPort.kt` | Resolver referencias del proveedor por el servidor bajo política de destinos permitidos |
| Presentación e historial | `SpDecodeApp.kt`, `HistoryRepository.kt`, componentes de resultados | Permanecen en Android; sin rediseño |

El listado de 240 rutas **no** debe tomarse como el número total de funciones finales de la API. Las importaciones especiales y los protocolos de texto son capacidades adicionales obligatorias. Cuando C1 defina `GET /api/v1/capabilities`, devolverá familias/variantes realmente habilitadas; no afirmará certificación por el solo hecho de estar registradas.

## 4. Resultado C0.4: corpus de paridad y sus límites

Las pruebas ya presentes serán la referencia inicial, sin cambiar los decodificadores:

- `tests/golden/manifest.json`, `tests/golden/expected/` y `tests/golden/a23_*.py`: 60 casos positivos sintéticos, hashes SHA-256 sobre entrada y salida.
- `tests/test_android_b_generic_parity.py`, `tests/test_android_c_ultra_parity.py`, `tests/test_android_d_renz_parity.py`: motores de perfiles.
- `tests/test_android_e_special_parity.py`, `tests/test_android_f_independent_parity.py`, `tests/test_android_g_text_parity.py`: familias posteriores.
- Pruebas instrumentadas de Android para `.hc`/HWID, `.npvs`, `.lnk`, `.ehi`, TLS, DarkTunnel, JSON completo, textos y NUR.
- `tests/test_cloud_c0_inventory.py`: verifica inventario, correspondencia con scripts, nueve hashes UI y disponibilidad/integridad del corpus existente **sin descifrar muestras**.

**Modelo de comparación C2–C4:** cada caso tendrá `format/variant`, entrada sintética o legalmente autorizada, `referenceResult.rawText` íntegro, JSON estructurado cuando sea aplicable, estado de error y hash del resultado de referencia. Se compararán bytes exactos de `rawText` y campos/orden pertinentes; queda prohibido sustituir errores por JSON parcial o truncar valores cifrados silenciosamente. La suite C0 verifica metadatos y fuentes, **no** prueba todavía la API ni acredita compatibilidad Cloud.

Condiciones negativas adicionales a cubrir: entrada inválida, extensión compuesta, archivo demasiado grande, versión desconocida, contraseña/HWID erróneos, doble bloqueo, timeouts, caída de conexión, importador externo no disponible, cancelación y lotes.

## 5. Resultado C0.5: localización y clasificación de superficies sensibles

No se trasladan valores ni se publican secretos en esta fase. Los principales **nombres de activos de origen** auditados son:

| Activos / fuentes de la app | Riesgo de mantenerlos en APK Cloud | Destino recomendado |
| --- | --- | --- |
| `embedded_kotlin_profiles.json`, `generic_b_profiles.json`, `ultra_c_profiles.json`, `renz_d_profiles.json`, `flex_f_profiles.json` | Perfil/algoritmo recuperable mediante ingeniería inversa | Workers |
| `hc_source_keys.json`, `http_tweak_source_tables.json`, `legacy_epro_npv2_keys.json` | Constantes de algoritmos y tablas embebidas | Workers |
| `npvs_v5_tables.b85` y tablas generadas | Tablas de descifrado incluidas en el paquete | Workers |
| `nur_tunnel_server_endpoint.json` | Información de integración accesible desde cliente | Configuración de backend cuando proceda |
| `HttpInjectorCloudPort.kt` | Constantes y lógica de proveedor accesibles en cliente | Servicio controlado del backend |
| `DevicePrivateCredentialVault.kt`, `SecureDecodeHistory.kt` | Secretos aportados por usuario e historial personal | Permanecen cifrados localmente según necesidades, sin formar parte del motor Cloud |
| `android/app/build.gradle.kts` / Secure Asset Vault | Ofuscación reversible, no barrera criptográfica frente al dueño del APK | Quitar activos de descifrado del AAB en C5 |
| Certificado de firma, `BuildConfig`, endpoint público | Identificadores públicos, **no** secretos privados | Identidad/verificación, no autenticación por secreto embebido |

**Regla operativa:** la biblioteca `libspdecode.so` de C4 podrá incluir URL pública de API, validaciones de TLS, estado de sesión y serialización, pero no llaves privadas de API, claves descifradoras compartidas ni secretos permanentes. La autorización y las claves confidenciales se emitirán/mantendrán en el servidor. No cambiar el esquema visual existente debe convivir con obligaciones de información y consentimiento del tratamiento online de archivos antes de producción.

## 6. Controles automáticos C0

`scripts/cloud_c0_inventory.py` (Python estándar) lee el catálogo existente, verifica las 239 correspondencias contra `spdecode.registry`, valida `.solid`, comprueba que existen los scripts de origen, genera el CSV determinístico, supervisa los entrypoints y clasifica **solo nombres** de materiales embebidos.

`docs/cloud/C0_UI_BASELINE.json` bloquea nueve archivos de UI/UX mediante identificadores de objeto Git. Son verificaciones de identidad de fuente (SHA-1 de Git), no de seguridad criptográfica. Cualquier rediseño exigiría aprobación explícita y rebaseline separado. La migración del transporte Android podrá ocurrir en `MainActivity.kt` sin cambiar interfaz.

Comandos para ejecutar desde la raíz del repo:

```bash
PYTHONPATH=. python scripts/cloud_c0_inventory.py --check
PYTHONPATH=. python -m unittest tests.test_cloud_c0_inventory -v
```

Para **regenerar deliberadamente** el inventario después de revisar diferencias:

```bash
PYTHONPATH=. python scripts/cloud_c0_inventory.py --write
```

La comprobación también se ejecuta en `.github/workflows/cloud-c0-audit.yml`; el resto de workflows y el bot no se alteran.

## 7. Condiciones para iniciar C1

- [x] Matriz de 239 + `.solid` versionada (C0.1).
- [x] Referencias Python/Node/PHP y fuentes de ejecución identificadas (C0.2).
- [x] Entradas de archivo/texto/importación especial localizadas (C0.3).
- [x] Corpus golden existente inventariado y controles estáticos incorporados (C0.4).
- [x] Materiales embebidos clasificados por ubicación, sin extraer valores (C0.5).
- [x] Archivos UI/UX base fijados y fuera del diff de C0.
- [ ] CI del PR en SUCCESS y revisión de su diff.
- [ ] Aprobación para iniciar infraestructura C1; **no desplegar aún**.
- [ ] Suite cliente ↔ API de comparación real, a implementar durante C2–C4.

**Nota sobre certificados de compatibilidad:** que C0 figure integrado no significa que se haya probado un servidor nuevo. C0 cierra el alcance y el punto de comparación; C1–C4 construirán los servicios y demostrarán la paridad. La meta final permanece: toda capacidad de descifrado actualmente disponible en Android operará desde el servidor y la app seguirá usando el mismo diseño.
