# SP-DECODE Cloud — C2: motores, texto y paridad de origen

**Rama:** `feat/cloud-c2-decoder-workers` (apilada sobre C1 y C0).  
**Alcance:** backend para la futura aplicación Android online. **No** modifica Android/UI/UX, bot, motores originales ni genera `libspdecode.so`.  
**Entorno:** worker privado; la API pública continúa en `503 CLOUD_NOT_READY` hasta completar autenticación y políticas C3.

## Resultado implementado

### C2.1–C2.3 — Dispatcher de formatos y runtimes

- `cloud/workers/python/engine.py` lee la **matriz C0** de 239 entradas Android + `.solid`. Selecciona de manera exacta uno de los **77 scripts originales** (Python, JavaScript/Node y PHP) por sufijo, sin permitir rutas de disco ni parámetros de intérprete aportados por el usuario.
- El proceso se ejecuta por petición en un directorio temporal privado, con límites de tamaño (**16 MiB máximo global de entrada, sujetos a menores límites por formato en C3**), **20 s de tiempo**, **4 MiB máximo de salida**, límites CPU/archivo/descriptores y `stdin=DEVNULL` salvo el adaptador credencial HCCFG.
- Solo el resultado estándar se devuelve como `rawText` UTF-8, íntegro, manteniendo espacios y saltos de línea; `structuredJson` se adjunta únicamente cuando **la salida completa** es JSON válido. Nunca se inferirán campos inexistentes o resultados parciales; `isPartial=false` corresponde a un proceso exitoso y su salida completa, **no** garantiza certificación del exportador.
- No se registran cuerpos de entrada, credenciales, stdout ni stderr. Un error interno se representa con un código seguro, no con trazas o material criptográfico.
- La imagen `cloud/workers/python/Dockerfile` conserva los scripts originales **en el servidor**, usa Node 22, PHP CLI y dependencias Python, con contexto Docker allowlist. El contenedor no publica puerto al host ni tiene acceso externo por defecto.

**Distinción indispensable:** registrar 240 rutas de ejecución no significa que 240 exportadores reales estén probados. Todos los métodos de archivo se asignan a su motor de fuente; la compatibilidad real debe demostrarse por muestra y versión. Quedan casos especiales Android-only que no se resuelven por un script estándar.

### C2.4 — Protocolos de texto

- `text_bridge.py` despacha mediante módulos originales desacoplados de Telegram: TLS, SSC Custom, DarkTunnel, NetMod, AR, PB, Howdy, ZIVPN, VMess, Flex, NPVS, SlipNet, V2Box, Kivu, Creeb, RENZ/7NET, XOR, Falcon Tunnel, NPVT/DNS, IZPH, WyrLite/WyrVPN, IntVPN, JuanScript/Mobi y EUT (según alias realmente reconocido por cada motor).
- No hay búsqueda ciega de claves ni fallback entre familias ajenas.
- Se prueban los vectores sintéticos de `scripts/android_g_text_fixtures.py`. Los enlaces HAPP que requieren clave RSA privada legítima **no** se declaran soportados ni exitosos sin provisión segura.

### C2.5 — Casos especiales de Android

- `.hc` tradicional: conserva el script `HTTPCUSTOM.py`.
- **HTTP Custom HCCFG 7.11.19 y protecciones:** `hc_bridge.py` reutiliza `_hc_hccfg.decrypt()` para contraseña, HWID y doble bloqueo; credenciales viajan por **stdin** del proceso hijo, nunca por argumentos, logs o variables de entorno. Las causas `PASSWORD_REQUIRED`, `HWID_REQUIRED`, `HWID_PASSWORD_REQUIRED`, `AUTH_FAILED` se devuelven como códigos, sin resultados parciales.
- `.solid`: ejecutado por el motor original `nur_tunnel_solid.py`.
- **Catálogo NUR Tunnel:** `catalog_bridge.py` abre y autentica el mismo sobre cifrado que `.solid`, pero verifica schema **Version / Servers / Networks**; nunca acepta un perfil como catálogo. Recibe bytes ya descargados: **no** recupera URLs de Internet.
- **HTTP Injector Cloud:** todavía no se realiza la importación remota. La implementación de red debe incorporar allowlist de proveedor, bloqueo SSRF, límites y consentimiento en C3.
- La página web pública y el cliente Android se mantienen sin activar descifrado. C3 debe poner autorización, cuotas, validación y políticas de privacidad **antes** de conectar el endpoint público.

## Seguridad / separación de responsabilidades

| Capa | Función C2 |
| --- | --- |
| API Next.js pública | `503 CLOUD_NOT_READY` para subir archivos, textos o credenciales |
| Worker `/health` | Liveness pública solo en red Docker privada |
| Worker `/ready` | Solo 200 con token interno de al menos 32 caracteres e inventario íntegro |
| `/internal/v1/capabilities` | Solo para solicitantes que conocen el token del worker |
| `/internal/v1/decode/file` | Formato y datos Base64; `credentials` opcional únicamente para `.hc` |
| `/internal/v1/decode/text` | Texto de esquema limitado; sin importaciones de Telegram |
| `/internal/v1/decode/import/catalog` | Solo bytes cifrados NUR; sin acceso a URL |
| Ejecutor | Rutas fijadas, control de tamaño/tiempo y descartes de archivos temporales |

El token del worker se inyecta por variable de entorno `CLOUD_WORKER_TOKEN` al desplegar la infraestructura interna; nunca va dentro de Android ni de `libspdecode.so`. Ausencia de token implica rechazo de toda petición interna de descifrado. **Este token de C2 y la red interna no sustituyen el sistema de autenticación/autorización de C3**.

El repositorio actual incluye los algoritmos de descifrado originales en código fuente. Si deben permanecer realmente confidenciales frente a terceros, habrá que controlar también la visibilidad/repositorio/deployment del backend. Sacarlos del APK **no** los hace privados mientras sigan accesibles públicamente en Git.

## Pruebas y diferencias conocidas

Comandos reproducibles desde raíz:

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest discover -s cloud/workers/python -p 'test_*.py' -v
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_cloud_c2_golden -v
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_cloud_c2_text tests.test_cloud_c2_hc tests.test_cloud_c2_nur_catalog -v
docker compose -f cloud/compose.yaml config --quiet
docker compose -f cloud/compose.yaml build decoder-worker
```

- `tests/test_cloud_c2_golden.py`: ejecuta las **60 muestras sintéticas A.2.3** tanto en el worker como en el **script original sin modificaciones** y compara la salida UTF-8. Para `.ssh`, el script histórico selecciona al azar **solo el emoji decorativo**; la comparación ignora exclusivamente ese marcador, sin alterar la salida real de la API.
- La referencia histórica A.2.3 de HTTP Tweak (`.ht` y `.htb`) difiere de la salida del script actual. Los snapshots se mantienen intactos, se informa del desfase y se compara con **el código fuente actual**, no se fuerza la conformidad modificando snapshots.
- `tests/test_cloud_c2_text.py`: vectores de textos Phase G generados desde los scripts originales; HAPP sin clave privada permanece rechazado.
- `tests/test_cloud_c2_hc.py`: HCCFG contraseña, HWID, doble cierre, entradas inválidas y rechazo de credenciales en formatos ajenos.
- `tests/test_cloud_c2_nur_catalog.py`: vector cifrado sintético de catálogo separado de `.solid`, validación AEAD y alteración de entrada.
- `cloud/workers/python/test_private_api.py`: token obligatorio, respuestas seguras y ausencia de servicio sin credencial.
- `cloud/workers/python/test_engine.py`: rutas, entornos limpios, tamaños y fallos.
- `.github/workflows/cloud-c2.yml`: paridad de origen, Phase G, HCCFG, NUR, Docker y red privada.

## Estado y condiciones antes de C3

C2 crea **la infraestructura de ejecución y rutas privadas**. No constituye aún un servicio Cloud accesible a usuarios; la aplicación Android sigue usando su comportamiento local anterior. Se requiere concluir y revisar los CI del PR.

**Trabajo aún no verificado o pendiente antes de habilitación pública:** cobertura de variantes reales de todos los formatos, comparaciones byte a byte Android ↔ worker donde el propio Android tenga una representación particular, importer HTTP Injector Cloud y política anti-SSRF, credenciales de usuario en el transporte HTTPS público, respuestas de error con UI actual, desempeño en VPS y protección del backend fuente. Esto será tratado en C3–C4 y en las subfases de paridad que resulten necesarias.

**Sin cambios de diseño ni modificaciones al bot.** El futuro cliente nativo se llamará `libspdecode.so`; las claves maestras del servidor nunca se compilarán en ese binario.
