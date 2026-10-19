# Validación — AustroPlus VPN 13.0.1

## Fuente y funciones verificadas

- ZIP recibido, 43104558 bytes, SHA-256:
  `c74e030baa126476dc1a41277f304715a6c2fda0b8074865c3bdbde5829a66c9`.
- `base.apk`, 24263686 bytes, SHA-256:
  `31664f1beffe1acf175b467397f70924087434518c17a145fcdafee6ab234871`.
- Paquete `xyz.tekidoer.austroplus.vpn`, versión 13.0.1, versionCode 13.
- Icono, 16607 bytes, SHA-256:
  `a687fb12a77d7ea952e1db4675fb2bfd484940bb395bcd5386aa020118a87736`.

Se resolvieron 5052 constantes mediante Java `Random` y el flujo original de
`a30`/`z20`. La salida del bucle que elimina NUL finales se confirmó en el DEX
(`if-nez` a la creación de String), porque JADX omitía ese salto en el Java.
No se ejecutaron ni modificaron controles de firma, protección o conexión VPN.

Rutas revisadas en el APK:

- `ExportActivity.p()` → `o8.b()`: `CONFIG`, campos con `wc0.l()` y AES-GCM.
- `MainActivity.B()` → `o8.a()`: autenticación GCM y lectura de `CONFIG`;
  contraseña/HWID/caducidad se evalúan después de descifrar el contenido.
- `MainActivity.A()/Q()` y `wc0.k()`: doble Base64 y servidor como cadena JSON.
- `sa.a()` → `m83.j()`/`m83.i()`: catálogo XXTEA estándar desde `system.db`.
- `MainActivity.c0()` → `ow0.a()` → `v8.run()`: GET y mismo descifrado del
  catálogo remoto. Sin cuenta ni identificadores de dispositivo para el GET.
- `MainActivity.Y()`, `ys.h()` y `oa.a()/b()`: campos Base64/XOR con clave de
  seis bytes. Los puertos y los nombres no usan esa transformación.

## Paridad completa con muestras reales

| Muestra | Bytes cifrados | SHA-256 | Resultado |
| --- | ---: | --- | --- |
| `ej.c`, inicial | 1416 | `b8051a9ba983b5679ebc02fc2f9051a9d6b3b17baecc9f0e83003fa352f811e6` | 1 servidor / 1 tweak |
| GET original HTTP 200 | 87705 | `07723fcbe2a950bc75f321ad06f91245a4d923f4bda7eb10ae911d048d4c9e5e` | 6 servidores / 198 tweaks |

El sobre se ejecutó con **`m83.a/i/j/n` originales**; todos los campos
protegidos se compararon con **`ys.h()` original**. Se contrastaron 6 / 503
ubicaciones, incluidas vacías (5 / 338 no vacías), sin recortar listas. Ambos
JSON completos coinciden, incluyendo tipos y metadatos. Salida: 1076 / 64457
bytes. Ambos pasan también por el subproceso Cloud real con igualdad completa
e `isPartial=false`. El CLI sin argumentos se prueba con descarga real.

## Pruebas reproducibles

```bash
python -m pip install -r requirements.txt
python -m unittest tests.test_austroplus_vpn -v
```

`tests/golden/austroplus_vectors.json` usa exclusivamente dominios `.invalid`,
credenciales falsas y metadatos sintéticos. Incluye perfiles con/sin servidor,
restricciones y vacíos; fixtures inválidos conservan etiqueta GCM válida para
comprobar validación real del JSON, no solo rechazo de ruido.

`tests/golden/austroplus_oracle.java` conserva las funciones Java de XXTEA,
AES-GCM, XOR y doble Base64 del APK. Solo se adaptan Android Base64 a JDK y las
declaraciones checked `throws` para compilar. La función inversa de XXTEA
produce catálogos sintéticos y se comprueba con el descifrador original. No
importa el lector Python ni material de cuenta. Java es opcional para el
verificador de pruebas y no se necesita para ejecutar los lectores.

Cobertura:

- Igualdad del JSON completo, Unicode/emoji, campos desconocidos y tipos.
- Servidor JSON conservado como cadena, con XOR aplicado solo a campos reales.
- Contraseña/HWID/caducidad y todos los vacíos conservados.
- Etiqueta, nonce y criptograma GCM alterados o truncados.
- JSON duplicado, profundo, no finito, Unicode inválido y campos mal formados.
- Catálogos y perfiles intercambiados: rechazo sin resultados parciales.
- BOM, Base64 sin padding y saltos de línea Android.
- URL fija, límites de descarga, compresión, redirecciones, HTML y HTTP fallido.
- Bundle extraído fuera del repositorio sin `PYTHONPATH`; catálogo con `-S`.
- Icono original, checksum y primitiva `ec.py` sin modificaciones.
- Rutas Cloud aisladas y salida histórica `.aro` idéntica al snapshot C2.

Límite de certificación: no se recibió un `.aro` exportado de forma
independiente; se verificó el Java original del cifrador con perfiles
sintéticos y se deja `exporterCertified=false`. Los datos reales del catálogo,
APK y bibliotecas permanecen fuera de Git, fixtures y paquete descargable.

## Resultado local final

19 de octubre de 2026: **650 pruebas Python**, correctas con **9 omisiones
existentes**, incluidos **14 controles AustroPlus** y el oráculo Java. Worker
**11**, VPS/QA **39**, gates Cloud **4**, Node **70**, todos correctos;
`npm run build` satisfactorio. CLI real con `python -S`: mismo JSON íntegro que
el oráculo. Bundle fuera del repositorio comprobado sin `PYTHONPATH` heredado.
Se mantienen los avisos históricos C2 sin modificar snapshots. No se compiló
ni ensayó Android en este análisis; no hay cambios de código Android.
