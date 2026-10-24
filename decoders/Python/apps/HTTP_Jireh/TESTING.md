# Verificación — HTTP Jireh 2.0

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
