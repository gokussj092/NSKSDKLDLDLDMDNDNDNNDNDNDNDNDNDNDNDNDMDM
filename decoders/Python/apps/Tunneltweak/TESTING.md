# Verificación — Tunneltweak 6.2.1

## Fuente y evidencia

APK base SHA-256:
`24f6bc80f2b6c53e44d4da4ade270b58da451449f149b84ef17f34ae3be4019e`.
Paquete `com.tunneltweak.loyalteams`, 6.2.1 (51). Análisis estático de
`ConfigManager`, `SecureConfigEncryption`, `ServerConfigManager`, los dos modelos,
`MainActivity`, `CloudConfigClient` y manifest. No se ejecuta ni modifica el APK.

`tests/golden/tunneltweak_oracle.java` conserva literalmente los métodos de
cifrado/descifrado Java recuperados, excepto el adaptador Android Base64 → JDK.
La extracción de los métodos evita dependencias Android; no simula la UI ni
certifica su comportamiento de importación. Los vectores en
`tunneltweak_vectors.json` son enteramente sintéticos. Las llamadas Java de
cifrado del APK produjeron archivos CBC, TTPBE1 y XOR y catálogos GCM con clave
pública y clave de prueba. Los seis documentos completos coinciden con Python,
incluyendo contraseña Unicode, texto multilínea y metadatos de protección.

## Catálogo real

GET al endpoint fijo con las cabeceras originales: HTTP 200,
15497 bytes, SHA-256
`bbf78e2bb10c8f8222270e0e2e48bd54d509e884260e59cea6af77654dfef4a2`.
Observado el 2026-10-20 UTC; el proveedor puede cambiar la respuesta.

Java descifró el campo `data` original con `SecureConfigEncryption.decrypt`.
Paridad completa con Python: **1 servidor y 53 configuraciones**, además de todo
el sobre, anuncio y valores/tipos. Se comparan objetos completos, no nombres o
recuentos aislados. No hay muestra local incrustada: falta el asset
`data_encoded.txt` que busca el fallback del código.

## Pruebas reproducibles

```bash
python -m unittest tests.test_tunneltweak -v
```

- Tres variantes `.tut`, clave correcta/incorrecta, ausencia de contraseña,
  alteración de salt, nonce, ciphertext y tag sin fallback desde TTPBE1.
- Catálogo GCM público/clave de prueba, Base64(JSON), JSON directo, sobre `data`,
  metadatos, servidor invisible, tipos y claves desconocidas sin pérdidas.
- Salt GCM cuyo primer byte es `{`, para evitar confundirlo con JSON heredado.
- JSON duplicado, NaN/Infinity, Unicode inválido, versión incompatible,
  profundidad, tamaño, padding, Base64 y archivos truncados.
- CLI desde otro directorio sin PYTHONPATH, contraseña en archivo local,
  errores sin valores de entrada, worker aislado y flujo de contraseña.
- Igualdad byte a byte con la CLI C0 para `.tut` DES bruto, Base64 DES,
  Base64 multilínea y GCM genérico de tres segmentos; motores antiguos intactos.
- Descarga con dos destinos fijos, cabeceras, validación de UUID, clave propia,
  rechazo de redirecciones, HTML, compresión y exceso de tamaño.
- Cloud UUID: respuesta simulada completa; **no se proporcionó un UUID real**.
- Icono app/backend idéntico al PNG original recuperado.

No se aportaron exportaciones reales independientes, cachés de instalación ni
una clave de suscripción real. Las pruebas de archivos y catálogo con clave de
suscripción usan vectores sintéticos. No se comprueba conexión VPN ni se afirma
que el catálogo público represente todos los planes de suscripción.

## Resultado de la entrega

- Suite Python principal: **694 pruebas, 9 omisiones existentes**, sin fallos.
- Worker: **11**; VPS/QA: **39**; gates Cloud: **4**; Node: **74**, sin fallos.
- Build web de producción correcto. Rutas históricas y Android sin cambios.
- CLI con GET real y worker aislado coinciden con todo el JSON del oráculo Java,
  incluyendo anuncio, un servidor y 53 configuraciones; `isPartial=false`.
- El broker Node conserva validación DNS/IP pública, TLS y cabeceras fijas,
  cubiertas por las pruebas de transporte. Su intento de GET directo en este
  entorno devolvió `REMOTE_NETWORK_DENIED`: el resolver nativo informa
  `EAI_AGAIN` tanto para tunneltweak.com como para raw.githubusercontent.com.
  La descarga Python funcionó mediante el proxy configurado del entorno. No
  se relajaron controles ni se declara una prueba directa del broker en VPS.
- ZIP extraído fuera del repositorio y sin PYTHONPATH: los dos lectores
  autónomos coinciden con documentos completos (CBC, XOR, PBE con contraseña
  Unicode y catálogo real). La variante Cloud UUID y una suscripción real
  quedan con los límites de validación descritos arriba.
