# Verificación — HTTP Jireh 2.0 / 2.2

## Actualización 2.2 — 2026-10-31

La rama `feat/cloud-selector-private-card-notification-chime` está incluida
en `main`: comparación desde `5a1c93a483619370ab0a155ed3d0ecd19ee8169c`
hacia `f73c8821f2dfd1e59e32005fae0602bc93367e99`, sin commits por incorporar.
La corrección se prepara en `fix/http-jireh-current-method`, creada desde ese
SHA de `main`. No se modifica `main` ni se despliega en el VPS.

### Paquete y procedencia

- Google Play consultado directamente: versión 2.2, actualización 2026-10-23.
  El índice del buscador y varias fichas todavía mostraban 1.7: no se usaron
  como evidencia de la versión actual.
- Descarga: `https://d.apkpure.net/b/XAPK/com.jirehvpn?version=latest`.
- XAPK: 54988498 bytes, SHA-256
  `768e50e7dde95d4bd44af8ad540c050f47d51e645c02665d96588a89817e104c`.
- APK base: 31648852 bytes, SHA-256
  `0f47c48aa6ec20b3ed4d9ff8bad0a159b79bc68e94b49df3ac4789812eb948ea`.
- Manifest binario del APK: paquete `com.jirehvpn`, versión **2.2**, código **13**.
- Certificado extraído: SHA-256
  `c22f4a72f74b5bd6be76137ad8de8afc5c3904d11b33d1a3ce647cd02a5fac30`;
  SHA-1 `923055f9c21c47f19b52af6762e8908907dc6c68`, coincidente con el
  certificado publicado para las versiones anteriores en APKPure. Se verificó
  la identidad declarada y se extrajo el certificado; esto no equivale a una
  instalación desde Google Play ni a una prueba de ejecución en Android.

### Cambio observado

`res/raw/dnsd_conf` cambia `NETWORK` y `NETWORK2` desde GitHub a dos enlaces
Dropbox. `SSH_SSL` conserva la clave de campos anterior. Se usan las mismas
rutas y consultas con el host fijo `dl.dropboxusercontent.com`; ambas
respuestas fueron HTTP 200 sin redirecciones. No se acepta una URL del cliente
ni se conserva fallback a GitHub: su respuesta actual es válida pero obsoleta
(versión 1129, un servidor).

El codec existente descifra las cuatro fuentes 2.2 sin modificar las recetas:

| Documento 2.2 | Versión interna | Perfiles | Campos conocidos descifrados |
|---|---:|---:|---:|
| `assets/config/config.json` | 1 | 1 servidor | 16 |
| `assets/flags/st.png` | 30 | 1 usuario | 6 |
| `NETWORK` remoto | 1134 | 145 servidores | 2320 |
| `NETWORK2` remoto | 845 | 1 usuario | 6 |

Los cuatro JSON enteros se reconstruyeron con el oráculo JDK independiente y
se compararon con Python, preservando claves, valores, tipos y campos
desconocidos. Se contrastaron **2348 campos no vacíos**. Huellas de las
respuestas observadas (pueden cambiar después):

- Servidores: 410752 bytes, SHA-256
  `3b8f491964a550960444b3db843b6e74011fad922d9ee6a2734606032a431104`.
- Usuarios: 856 bytes, SHA-256
  `8e7c05b6b9c370078f5a8db1dc65089fb4eb16881fabea0b5af1ce77d22023d5`.

### Validación de la corrección

- Python 3.12, PyCryptodome **3.23.0**: las **13 pruebas** de
  `tests/test_http_jireh.py` pasan, sin omisiones, incluyendo GCM/DES,
  worker real, CLI, límites, rechazo de entradas inválidas, icono y Java.
- Node 24: **26 pruebas**, sin fallos ni omisiones, ejecutando
  `server-vpn-provider.test.mjs`, `http-jireh-remote.test.mjs` y
  `focus-vpn-cloud-remote.test.mjs`. Comprueban destino exacto, consulta,
  versión del agente, DNS público fijado, TLS, interruptor de despliegue,
  rechazo de redirecciones y ausencia de fuentes arbitrarias.
- CLI final sin argumentos y con `--users`: descarga real correcta desde
  los nuevos destinos; JSON completo idéntico a los documentos del oráculo.
- Worker aislado con bytes remotos reales: 145 servidores,
  `isPartial=false`, salida completa de 130904 bytes.
- El GET real del broker Node no pudo salir desde este entorno: su control
  de DNS produjo `REMOTE_NETWORK_DENIED` antes del transporte. No se debilitó
  ese control. La red se comprobó mediante el CLI Python; el enrutamiento y
  los controles del broker mediante las pruebas Node anteriores. Queda la
  comprobación del broker en el VPS después de un despliegue autorizado.

Cloud continúa descargando solo servidores; `--users` sigue siendo una
operación separada del CLI. No se cambia el catálogo público, sus interruptores,
el formato de respuesta, HPKE ni las reglas de V1/V2. No hace falta recompilar
Android para cambiar estas fuentes del servidor. No se lanzó GitHub Actions.
La importación de un archivo `.sks` exportado realmente por 2.2 y la conexión
VPN en dispositivo siguen pendientes; los vectores del importador son
sintéticos. APK, catálogos y resultados reales no se incorporan a Git.

## Evidencia histórica de 2.0 — 2026-10-19

## Evidencia independiente

Se analizaron las rutas del APK y los recursos originales, sin seleccionar
una receta por nombre o extensión. La constante exterior se recuperó ejecutando
el `toString()` de `C3941` en Java. `C3938` y `C3914` confirmaron `NETWORK` y
`NETWORK2`. Las clases de importación confirmaron GCM y DES separadamente.

`tests/golden/jireh_oracle.java` es una normalización legible de las operaciones
observadas, no ejecución del APK Android completo: adapta Base64 a JDK,
PKCS7 de AES a PKCS5 equivalente, elimina aplanamiento de flujo y usa JDK 17.
El oráculo normalizado y Python coincidieron en todos los campos y tipos de
cuatro documentos completos, conservados únicamente fuera de Git:

| Documento | Perfiles | Campos cifrados comprobados |
|---|---:|---:|
| Servidores incluidos | 1 | 16 |
| Servidores remotos | 109 | 1744 |
| Usuarios incluidos | 1 | 6 |
| Usuarios remotos | 1 | 6 |

Respuesta remota de servidores: 304817 bytes,
SHA-256 `52436366e4d55f4b96aa96f54310150cd295dd619c3ed378674ac95cb168aec0`.
Usuarios: 857 bytes,
SHA-256 `ee957523e7cc01b42734b9d9ea537cf84b17ef6c7d265c4465623c1761f8c744`.
Son huellas de la observación del 2026-10-19; la respuesta puede actualizarse.

## Pruebas reproducibles sin datos privados

```bash
python -m unittest tests.test_http_jireh -v
```

Los vectores versionados son exclusivamente sintéticos: sobre exterior,
ambos tipos de lista, los 16+6 campos, desplazamiento Java/UTF-16,
claves desconocidas, tipos JSON y archivos GCM/DES con XML completo.
Se comparan documentos enteros, CLI desde otro directorio sin PYTHONPATH,
worker aislado, icono y oráculo Java. Casos negativos: alfabeto, longitud,
padding, campos incompatibles, HTML, claves duplicadas, NaN/Infinity,
profundidad, límites, entidades XML y alteración de salt/nonce/tag sin fallback
DES. Las descargas solo admiten las dos URL fijas y rechazan redirecciones.

No hubo muestra de exportación real `.sks` ajena al generador de prueba ni
prueba de conexión VPN. La actividad exportadora no invoca un escritor en
su `onClick` observado; la compatibilidad declarada corresponde al importador.

## Resultado de la entrega

- Suite Python principal: **677 pruebas, 9 omisiones existentes**, sin fallos.
- Worker: **11**; VPS/QA: **39**; gates Cloud: **4**; Node: **72**, sin fallos.
- Build web de producción correcto. Android y motores históricos sin cambios;
  inventario C0 de 240 y C8 de 246 conservados. Los tres desajustes históricos
  del corpus C2 siguen registrados, sin regenerar sus snapshots.
- CLI con GET real: servidores y `--users` producen el JSON completo del
  oráculo. Worker aislado: 109 servidores completos, `isPartial=false`.
- Distribución ZIP extraída fuera del repositorio y sin PYTHONPATH: ambos
  lectores contrastados contra documentos completos; GCM, DES, catálogo
  de servidores y catálogo de usuarios. Solo se empaqueta código, icono y
  documentación públicos, junto con el soporte mínimo compartido.
