# SP-DECODE Play AAB 1.1.20 (build 31): todos los idiomas integrados

**Estado:** candidato privado en PR #100; **NO-GO para publicación pública** hasta autorización explícita del propietario.  
**Rama:** `feat/mm-tunnel-1-10-11-1-decoders` (base `main`; migrado desde PR #100).  
**Versión:** `versionName=1.1.20`, `versionCode=31`, paquete `com.ghostdeveloper.spdecode`.

## Motivo

En el AAB distribuido a través de Google Play, algunos usuarios podían elegir un
idioma dentro de Ajustes sin obtener la traducción correspondiente; la APK
completa no presentaba el problema. Android App Bundle puede usar divisiones
de recursos según el idioma del dispositivo. Esto es incompatible con el
selector de idioma interno si no se solicitan idiomas a Google Play.

## Cambio funcional único

`android/app/build.gradle.kts` utiliza:

```kotlin
bundle {
    language { enableSplit = false }
}
```

Conserva las traducciones XML ya existentes, sin modificar `SupportedLanguages`
ni descargar paquetes de idioma de Play. El paquete base instalado debe contener
los 14 idiomas: español, inglés, portugués (Brasil), árabe, persa, francés,
indonesio, ruso, alemán, turco, vietnamita, hindi, japonés e italiano.

## Verificaciones

- `python3 -m unittest tests.test_android_aab_languages -v`: detecta
  reducciones en el inventario, XML faltantes, divisiones activadas o metadata
  protobuf inválida.
- `python3 scripts/ci/verify_aab_locales.py app-release.aab`: abre el AAB real
  y verifica la configuración `LANGUAGE split` desactivada y la existencia de
  `base/resources.pb`.
- GitHub Actions: `Validate SP-DECODE` compila release APK y AAB en su smoke
  de Android. La compilación privada firmada también requiere ese control y
  conserva la keystore permanente.
- **Prueba manual todavía necesaria:** instalar una versión servida desde un
  AAB por Play (prueba cerrada), seleccionar japonés, árabe y otros idiomas en
  el dispositivo cuyo idioma del sistema sea español/inglés, reiniciar la app
  y comprobar que la interfaz mantiene la traducción.

CI no demuestra por sí solo que el paquete haya sido aceptado por Play ni
que se haya instalado en un teléfono real.

## Límites y distribución

El aumento del código de versión de 30 a 31 y el cambio de nombre a
1.1.20 **no implican publicación**. Ningún workflow sube automáticamente el
AAB a Google Play; la instalación desde Play y la aceptación de la firma
pertenecen a un proceso separado. No regenerar certificados ni reutilizar un
versionCode de un AAB publicado. No se modifica API, VPS, decodificadores,
credenciales, permisos ni el esquema de firma.

Después de aprobar el candidato en pruebas físicas, el propietario podrá
autorizar expresamente el envío a prueba cerrada o a producción.
