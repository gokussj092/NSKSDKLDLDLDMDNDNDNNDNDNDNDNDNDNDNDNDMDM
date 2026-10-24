# Android Cloud — Catálogo remoto de formatos (fase Android, 2026-10-23)

## Estado y alcance

Código incorporado en el PR #96 sin actualizar Play Store ni desplegar la VPS.
El contrato backend está definido en
`docs/cloud/C10_REMOTE_FORMAT_CATALOG_API.md`: versión única, `apps`,
`formats`, `formatDetection`, `formatCount`, `formatsSchemaVersion`.

- API: 250 extensiones registradas por el worker (240 rutas que históricamente
  contaban con referencia Android y 10 nuevas exclusivas Cloud).
- APK Cloud: solo metadatos descargados; las clases criptográficas locales
  permanecen excluidas del APK mediante `prepareCloudOnlySources`.
- APK no Cloud: sigue compilando los puertos de regresión histórica; **no**
  debe interpretarse como una opción activa en la APK distribuida.
- El asset `decoder_catalog.json` (esquema 4) conserva un respaldo de nombres,
  sufijos, estado local y fase; **no contiene** `script`,
  `originalRuntime`, `sourceCatalog` ni rutas Python.
- `AndroidOfflineDecoderRouter` mantiene la correspondencia de familias E/F
  por sufijo auditado, sin depender de datos descargados ni de rutas Python.
- El script interno `scripts/android_a24_catalog.py` sigue comprobando el
  inventario completo original con datos privados del repositorio; el
  generador público omite esos campos. `scripts/cloud_c0_inventory.py`
  mantiene la matriz C0 privada y verifica la igualdad del asset saneado.

## Descarga y consistencia

`ServerVpnCatalogRepository` valida **antes de almacenar** el esquema de
formatos, recuento, reglas de coincidencia, orden por longitud de sufijo,
unicidad, nombres, tipos y campos de credenciales. Solo acepta metadatos de
archivo y `cloudSupported:true`. Los campos desconocidos o rutas
ejecutables invalidan la respuesta completa. Las entradas nuevas se usan
solo para detectar la extensión; la API sigue siendo quien controla los
motores autorizados.

El mismo snapshot que conserva `apps` e iconos también conserva `formats`
cifrado mediante AES-256-GCM y Android Keystore. Si faltan formatos en un
snapshot antiguo, `knownVersion=0` obliga a solicitar el documento completo,
incluso si la versión pública no cambió. Si TLS, JSON, iconos o formato
fallan, se conserva el último snapshot verificado. No hay ejecución remota de
scripts, URL proporcionada por Android ni caché de credenciales.

La sincronización automática respeta el ajuste y consentimiento existentes.
Sin opt-in, la pantalla Formatos reutiliza el mismo botón de actualización
manual y confirmación; hasta instalar la nueva lista puede mostrar los
nombres de respaldo. Al cambiar la versión, `/watch` y WorkManager
recuperan la nueva lista cuando están habilitados.

## Interfaz y alertas

La UI de nueve archivos C0 congelados permanece íntegra (sin rebaseline
del hash `SpDecodeApp.kt`). Gradle inyecta exclusivamente en la variante
Cloud el argumento `fileFormats`, su nueva fuente en la pestaña
Formatos y el mismo botón de actualización que utiliza Server VPN.
No se cambiaron colores, tamaño o estructura de las alertas.

Archivos con extensión desconocida y protocolos de texto desconocidos
muestran avisos localizados específicos con acceso existente a
**Contactar al desarrollador**. No se registran como fallos internos.
Contraseñas incorrectas, NPVS protegido y otras credenciales mantienen
sus avisos especiales (sin botón innecesario de reporte). Los errores
`REMOTE_NOT_CONFIGURED`, `REMOTE_CONFIG_UNAVAILABLE`,
`REMOTE_DECODER_FAILED`, `REMOTE_INTEGRITY_FAILED`, referencias
inválidas y errores de red de HTTP Injector Cloud tienen clasificación
separada. Se añadieron recursos en 14 idiomas.

## Validación obligatoria antes de distribución

```bash
PYTHONPATH=. python scripts/android_a24_catalog.py
PYTHONPATH=. python scripts/cloud_formats_catalog.py
PYTHONPATH=. python scripts/cloud_c0_inventory.py --check
PYTHONPATH=. python -m unittest tests.test_android_a24_catalog tests.test_android_remote_formats tests.test_cloud_c0_inventory tests.test_cloud_c8_android_input_routes -v

# Dentro de cloud/web:
node --test tests/file-formats.test.mjs tests/server-vpn-catalog.test.mjs

# En el job C5 con SDK/NDK:
SPDECODE_CLOUD_API_BASE_URL=https://api.spdecode.example gradle --no-daemon :app:assembleDebug
```

QA dispositivo: instalar desde una versión anterior con caché antigua; forzar
refresh manual con autoactualización apagada; añadir nueva extensión Cloud
y verificar que se detecta sin APK nueva; importar un archivo desconocido y
un protocolo de texto no reconocido; comprobar enlace Contactar; verificar
`.sksrv.png`, `.fɴ`, `.npvs`, archivos de contraseña y errores de
HTTP Injector Cloud; fallar red/JSON icono para comprobar recuperación,
y comparar Español/Inglés/los otros 12 idiomas. Verificar que el Android
Cloud resultante no empaqueta scripts ni motores nativos históricos.

**No confundir una integración en PR con una APK producida o desplegada.**
No fusionar, desplegar, anunciar novedades ni subir a Play antes de pasar CI
y QA de dispositivo.
