# SP-DECODE Offline — Migración a C++ nativo

Rama: feat/version-offline-apk. La variante nativa solo se selecciona con
SPDECODE_OFFLINE_NATIVE=true, sin SPDECODE_CLOUD_API_BASE_URL.
Integración alfa C++ para HC, EHI, NetMod y familia NPV. Las pruebas de paridad Linux no sustituyen una certificación con exportaciones reales en Android.

## Aislamiento de distribución
- Identificador: com.ghostdeveloper.spdecode.offline
- Etiqueta del launcher: SP-DECODE Offline
- Fuentes: android/app/src/offlineNative/java; biblioteca liboffdecode.so.
- Sin permiso INTERNET, cliente Cloud, catálogo VPN ni decodificadores antiguos de Kotlin.
- El motor Cloud y los métodos Python no se modificaron.
- El resultado NetMod conserva el JSON original completo (no el resumen aplanado del bot).
- El usuario debe proteger cuidadosamente las claves privadas NPV exportadas.

## Estado real
| Función | Estado | Método Python de referencia |
|---|---|---|
| NetMod Syna .nm | C++ AES-128-ECB/PKCS7 integrado, pendiente QA de Android | decoders/Python/nms.py |
| NPV generador P-256 | C++ clave pública SEC1 comprimida, privada PKCS8, pendiente interoperabilidad | decoders/Python/npvs_identity.py |
| HTTP Custom .hc legacy | C++ XOR/ChaCha20 64-bit nonce/AES-RST/JKL integrado; golden sintético validado, QA Android y variantes reales pendientes | decoders/Python/HTTPCUSTOM.py |
| HTTP Custom contraseña/HWID/ambos | C++ HCCFG 1/2/5/7 y HCX4 10 n11/n12; Argon2id+XChaCha20-Poly1305; paridad Linux sintética validada, QA Android pendiente | cloud/workers/python/hc_bridge.py |
| HTTP Injector .ehi | AES-CBC, XXTEA, XOR de campos, Argon2id y XChaCha20-Poly1305 C++ integrados; bypass y estándar validados con vectores sintéticos | decoders/Python/HTTPINJECTOR.py |
| NPV Tunnel .npvs v1 | C++ firmado ECDSA P-256, contraseña PBKDF2, appkey whitebox, AEAD ChaCha20-Poly1305, descifrado íntegro y campos npvs1 | decoders/Python/npvs_v1.py |
| NPV Tunnel .npvs v5 | C++ firma ECDSA, clave de app whitebox, contraseña, destinatarios ECDH/AES-GCM, metadatos, inventario HMAC y campos AEAD | decoders/Python/npvs.py |
| NPV Tunnel .npvs v6 | C++ firmado, destinatario ECDH y máscara de vinculación whitebox; modos v6 no certificados por el servidor se rechazan | decoders/Python/npvs.py |
| NPV Tunnel NPVT1/NPVTSUB1 | C++ whitebox CTR histórico; objetos y listas JSON completos; sin firma de autenticación original | decoders/Python/NPVTUNNEL.py |
| NPV enlaces de texto | C++ Base64 JSON y npvs1 anidados, transporte NPVS delegado al verificador firmado | decoders/Python/apps/NPV_Tunnel/text_decoder.py |

El JNI rechaza explícitamente los formatos pendientes. No habrá fallback a Kotlin ni Cloud.

## Condiciones para declarar la versión terminada
1. GitHub Actions compila y verifica package, firma, ausencia de INTERNET y liboffdecode.so.
2. Pruebas diferenciales C++/Python para .nm con archivos legítimos, errores de Base64, padding y tamaño.
3. Interoperabilidad P-256 comprobada con npvs_identity.normalize y Android NpvsIdentityVault.validate.
4. Motor HC C++ integrado; 69 casos sintéticos Python/C++ pasan en Linux. Falta validar compilación y ejecución en Android, exportaciones legítimas actuales y versiones legacy adicionales.
5. Los puertos EHI y NPV se validan con regresión sintética en Linux y compilación Android. FALTAN pruebas con exportaciones legítimas actuales en un teléfono antes de certificar todas las versiones del servidor.
6. No publicar una compilación final de cuatro métodos hasta pasar los controles anteriores. Las versiones NPVS v6 no verificadas por Python NO se aceptan por heurística.

## Tablas y seguridad

- `scripts/build_offline_npv_tables.py` extrae literales auditados del servidor; valida hash SHA-256 de tabla moderna, tamaños v1 y pickle histórico solo con un Unpickler de datos. ÚNICAMENTE durante la compilación en GitHub Actions.
- En Android solo se incluye el código C++ y bytes de tabla en `liboffdecode.so`; no se ejecuta Python ni pickle.
- Mbed TLS 3.6.7, Argon2id de referencia y zlib enlazadas en el binario nativo.
- Los NPVS firmados verifican ECDSA antes de derivación de claves o solicitar credenciales. Toda sección fallida provoca error, nunca JSON parcial.
- El esquema P-256 conserva el material privado dentro del proceso de análisis. No se incorporan claves privadas de prueba al paquete.



## SMART UI y Dark Tunnel offline (2026-11-08)
- Navegación: Inicio, Historial y Ajustes. Acerca de está anidado en Ajustes,
  con flecha y navegación Atrás del sistema. Se sustituyó la carga Compose de
  `mipmap/ic_launcher` (adaptive-icon XML, no compatible con `painterResource`)
  por el drawable vectorial `offline_launcher_foreground`. El fallo del
  dispositivo se atribuye a esa referencia por análisis estático; pendiente
  confirmación de no-crash en un dispositivo físico.
- Visor JSON: alto según líneas reales, con un máximo de 150 líneas visibles;
  conserva resultado completo seleccionable y desplazamiento si supera ese alto.
  Copiar/exportar no agregan paginación ni cortes.
- Dark Tunnel: módulo `spdecode_dark_tunnel.cpp`, AES-256-CFB exterior y
  AES-192-CFB anidado, Base64 seguro, MessagePack y normalización JSON.
  Extensiones `.dark`, `.dt`, `.dtunnel`; enlaces `dt://`, `dtunnel://`,
  `dark://`, `darktunnel://`, `dark-tunnel://` y envoltorios Base64 sin prefijo
  detectados por el campo estructural `encryptedLockedConfig`.
  NUNCA usar los algoritmos históricos de Kotlin en el APK.
- Gate diferencial: `tests/test_offline_dark_native_parity.py` compilado
  con `tests/native_dark_tunnel_cli.cpp`, contra casos sintéticos Python
  PyCryptodome/msgpack. Estos casos no equivalen a una certificación con
  exportaciones reales de Dark Tunnel.
- El archivo online y los motores Cloud no se tocan. R8 release requiere firma
  alfa de CI, NO la clave de distribución estable. Verificar instalación,
  pantalla Acerca de, desplazamiento JSON, formatos reales Dark y regresión
  del resto de métodos en Android físico antes de promocionar como estable.


## Offline file sharing, errors and Hat Tunnel (2026-11-08)
- External imports: ACTION_SEND and ACTION_VIEW intents are declared in the isolated Android manifest; MainActivity processes EXTRA_STREAM, data and ClipData both in onCreate and onNewIntent. Supports Telegram, WhatsApp and document providers granting file read access. Unknown formats show a modal alert and never use unrelated decoders.
- Readable errors: OfflineErrorMessages maps unsupported versions, invalid files, credentials and I/O failures to user-visible messages without raw exception codes. A file intended for another NPV recipient cannot be opened by creating a new key. Historical NPV recipient-v1 explicitly indicates unsupported protection.
- No implementation details in visible UI copy. The implementation stays offline and cryptographic decoding stays in C++ behind JNI.
- Native Hat Tunnel: .hat files, AES-128-ECB with PKCS7 unpadding, historical key, complete original JSON, and profilev5 XOR field interpretation. Independent golden tests live in tests/test_offline_hat_native_parity.py. Synthetic parity does not certify every real export.
- Dark Tunnel text: darktunnel:// already routed through the Dark native decoder; retaining other supported schemes.
- New UI contract: tests/test_offline_share_ui_contract.py checks intents, errors, Android isolation, and removal of UI implementation jargon.
- Device QA pending: import through Telegram/WhatsApp, malformed files, unsupported HC version, NPV mismatched identity, actual HAT file and regression on existing methods. Alpha release has an ephemeral test signing certificate; back up local results and NPV identity before uninstall.
