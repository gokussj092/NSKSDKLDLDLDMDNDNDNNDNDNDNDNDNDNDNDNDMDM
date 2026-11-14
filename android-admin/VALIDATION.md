# Validación del panel Android — 14 de noviembre de 2026

Rama: `feat/android-admin-panel`. Revisión ejecutada: `896580b7e750516f8cc4d58c97e0fb7fadd2863f`.

[GitHub Actions: ejecución 43632546712](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/43632546712): **SUCCESS**.

## Resultados observados

| Comprobación | Resultado |
| --- | --- |
| `assembleDebug` | PASS; bibliotecas arm64-v8a, armeabi-v7a, x86 y x86_64 compiladas |
| `lintDebug` | PASS; 0 incidencias en la revisión local de este código |
| `testDebugUnitTest` | PASS; 15 pruebas, 0 fallos, 0 errores |
| `assembleDebugAndroidTest` | PASS |
| `connectedDebugAndroidTest` | PASS; 12 pruebas, 0 fallos, 0 errores, 0 omitidas |
| Rutas C++ y puente JNI en JVM | PASS en CI; Kotlin/JNI/C++ también verificado localmente |
| Firma del APK entregado | PASS; firma de debug, esquema v2 |
| Alineación del APK | PASS; `zipalign -c -P 16 -v 4` |
| Permisos del APK | Sin INTERNET; solo el permiso interno de receptor no exportado |
| `git diff --check` | PASS |

Las pruebas instrumentadas se ejecutaron en Android 15 / API 35, emulador x86_64 con KVM. Se conservaron 26 capturas nativas: 22 secciones principales, dos capturas del chat compacto, modo horizontal y tema claro. Se revisaron las secciones comerciales, usuarios/personal/soporte y plataforma; las capturas finales confirman el mensaje enviado visible a 320 dp, texto al 130% y teclado abierto. No se sustituyó esa comprobación por un desplazamiento manual en la prueba.

La configuración compacta se aplica antes de lanzar la Activity. El chat sigue los cambios de altura del teclado y del borrador, reduce los espacios de las burbujas y mantiene la indicación de vista previa en el encabezado cuando el teclado está abierto.

## Cobertura

Las 15 pruebas de lógica comprueban importes exactos, IP literales, dependencias de permisos, CSV seguro, identidad de usuarios, conservación de Premium, mensajes locales, precios históricos de pedidos, exclusión de pendientes/reembolsados, claves DEMO, créditos, catálogo atómico, 14 idiomas y protección del cargo propietario.

Las 12 pruebas en Android comprueban la carga real del puente nativo, edición de usuario, chat/cierre de ticket, creación de cargo, precio del producto frente al pedido histórico, generación/revocación de licencia DEMO, validación de IP, publicación local del catálogo, aviso con 14 idiomas, recorrido de secciones, pantalla compacta con teclado y modo horizontal/tema claro.

## APK entregado

Se entrega el mismo `app-debug.apk` conservado por la ejecución aprobada, renombrado a `SP-DECODE-Admin-Preview-20261114.apk`.

- Paquete: `com.ghostdeveloper.spdecode.admin.preview`.
- Versión: `1.0.0-dev2-preview` (código 2).
- Tamaño: 19,299,329 bytes.
- SHA-256: `18772aee6cc5195586f60c1d5056b5c501427a604d2e5f0ff76446d1250a02d5`.
- Artefacto de CI: `14128454947`; SHA-256 del ZIP: `3fa40a8562c5eb78445418f58960cb12a883caa46cc45d0d14d6b266ba03c0dd`.

## Límites verificados

Este resultado valida una vista previa nativa interactiva con datos locales. No hay permiso INTERNET ni sesión real en la Activity. Los datos de demostración viven en memoria; solo persisten las preferencias de pantalla. Las claves generadas llevan DEMO y no conceden acceso real.

Siguen pendientes la autenticación administrativa remota, MFA, biometría, Keystore, autorización por permisos de servidor, pagos/licencias reales, chat remoto/adjuntos, recepción push y supervisión del VPS. No se han procesado cobros, reembolsos ni notificaciones reales. Release permanece deshabilitado. No se realizaron pruebas en hardware ARM físico.
