# C10 — API de formatos remotos (fase 1: solo backend)

## Contrato, compatible con APK anteriores

El endpoint existente `POST /api/v1/server-vpn/catalog`, con
`{"knownVersion":0}`, sigue devolviendo `apiVersion:"v1"`,
`catalogVersion`, `recheckAfterSeconds` y el mismo arreglo `apps`.
Añade tres propiedades públicas:

- `formatsSchemaVersion:1`: esquema del inventario de extensiones.
- `formatCount`: cantidad exacta de entradas.
- `formats`: arreglo de registros con `suffix`, `name`, `kind:"file"`,
  `offlineSupported`, `cloudSupported` y `credentialFields`.

La extensión `suffix` no incluye el punto inicial. La detección futura debe
normalizar solo el nombre base (no rutas), comparar ignorando mayúsculas y
elegir la coincidencia completa más larga: `name.sksrv.png` detecta
`sksrv.png`, no `png`. `kind:"file"` distingue archivos exportados
de protocolos de texto, que siguen su contrato independiente.

`offlineSupported` indica que la APK actual tiene una ruta nativa
incorporada, **no certifica la compatibilidad de todas las versiones del
exportador**. `cloudSupported` indica un motor registrado en el worker;
no es garantía de disponibilidad VPS ni éxito de cada archivo. Los campos
`credentialFields` son exclusivamente metadatos de interfaz permitidos
por el contrato del servidor, nunca claves o contraseñas.

Cuando `knownVersion===catalogVersion` se conserva la respuesta mínima
`unchanged:true` sin `apps` ni `formats`. El endpoint `/watch`
reutiliza la **misma versión**. Los clientes actuales ignoran las propiedades
adicionales y siguen cacheando sus proveedores; no necesitan una APK nueva
para conservar las funciones actuales.

## Inventario y regeneración

Las fuentes técnicas **privadas del repositorio** son
`docs/cloud/C0_FORMAT_MATRIX.csv` y los overrides C8 de
`cloud/workers/python/engine.py`. El estado nativo se contrasta con
`android/app/src/main/assets/decoder_catalog.json` y con la ruta
independiente `.solid`; no se ejecuta ningún decodificador durante la
generación.

```bash
python3 scripts/cloud_formats_catalog.py --write
python3 scripts/cloud_formats_catalog.py
cd cloud/web
node --test tests/file-formats.test.mjs tests/server-vpn-catalog.test.mjs tests/server-vpn-version-sync.test.mjs
```

El archivo generado `cloud/web/content/file-formats.json` publica solo
metadatos permitidos. **Nunca** publicar campos `script`, rutas de Python,
runtime interno, claves de cifrado, métodos criptográficos ni URLs de
proveedores. Los scripts viven en el backend; el catálogo es datos, no código.
C6 CI comprueba que el snapshot coincide con los motores registrados.
No añadir aliases no respaldados por un motor existente.

Un cambio en nombres/extensiones/capacidades cambia la huella persistente
del catálogo en `c12-provider-controls.mjs` y eleva la versión monotónica
sin borrar switches ni degradar versiones que ya hayan visto los usuarios.
La versión mínima de código de esta fase es **37**. Una nueva extensión C8
se integra en el worker, se regenera el inventario y se prueba antes de
desplegar. **No se permite activar motores arbitrarios desde JSON**.

## Pendiente: fase 2 Android

La APK actual **no** lee `formats`: guarda únicamente `apps`. Eso es
deliberado. En una actualización Android posterior:

1. Extender el lector de catálogo para validar y cachear `formats`
   cifrado junto con `apps`, conservando un snapshot anterior si falla.
2. Mantener y usar los decodificadores offline existentes, sin ejecutar
   scripts descargados; nuevos formatos Cloud detectados por sufijo se
   enrutarán a C8, sin prometer compatibilidad offline.
3. Migrar la selección de motores nativos que hoy depende de la propiedad
   `script` hacia IDs internos Kotlin y solo entonces retirar metadatos de
   ejecución de `decoder_catalog.json`.
4. Preservar `sksrv.png`, sufijos Unicode, precedencia de C8 y los avisos
   de contraseña, HWID y clave de dispositivo.

Ni Android ni el JSON local se modificaron en esta fase. No desplegar VPS,
publicar APK ni cambiar novedades sin autorización del propietario.

## Estado de verificación

La fuente generada contiene 250 sufijos únicos: 240 con ruta nativa
(`239` inventariados + `.solid`) y 10 exclusivos de Cloud; los 18
overrides C8 se deduplican. Esta cifra describe el inventario actual,
no una constante que deba congelarse en versiones futuras.
