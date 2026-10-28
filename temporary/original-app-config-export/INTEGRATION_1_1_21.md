# Integración de exportación compatible — 1.1.21 (32)

Implementación para pruebas en la rama temporal del repositorio migrado a Goku.
No despliega servicios, no publica APK/AAB y no fusiona a main. Las
notificaciones del teléfono quedan para una fase posterior.

## Comportamiento

1. El usuario importa un archivo y recibe su JSON mediante el flujo existente.
2. Con exportación habilitada, el worker prepara también el archivo compatible
   a partir de la fuente autenticada y sus secciones originales. No utiliza el
   JSON de presentación para reconstruir el contenedor.
3. En **Exportar** aparece **Exportar para HTTP Custom**, **Dark Tunnel**,
   **HTTP Injector** o **NPV Tunnel**, según la extensión. JSON y texto ordenado
   siguen disponibles; copiar conserva sus opciones anteriores.
4. El usuario elige el destino con el selector de archivos de Android. Se
   escriben bytes binarios y la extensión original, sin permisos de acceso
   general al almacenamiento.
5. El artefacto queda dentro del registro AES-GCM del historial privado,
   excluido de backup Android. Puede exportarse después de reiniciar y desde
   el menú de ese registro. Favoritos, retención y eliminación operan sobre
   el registro completo. No se guardan credenciales de apertura en él.

Los registros anteriores, resultados de texto, importaciones remotas y
catálogos agregados que no contienen un artefacto necesitan volver a importar
el **archivo original** para este flujo. No se generan archivos compatibles
con datos faltantes. La exportación corresponde al resultado guardado;
esta entrega no añade un editor arbitrario de JSON.

## Alcance de formatos

| Extensión | Ruta habilitada | Nota | Protección de apertura |
| --- | --- | --- | --- |
| `.hc` | HCX4/HCCFG 10, build 899, n11/n12 admitidos por las guardas; salida n11 abierta | HTML oficial reemplaza/inserta la nota | Retira password y HWID tras autenticarlos |
| `.dark` | JSON abierto y variantes SSH/VLESS observadas de Dark Tunnel, wrapper sin expiración | Sin banner | Conversión abierta observada |
| `.ehi` | Variante auditada de Injector 6.5.0/244; ruta E aceptada, HMAC recalculado | HTML oficial | Opciones abiertas observadas |
| `.npvs` | NPVS v5 app-key/passphrase y v5/v6 recipient compatibles con el lector; salida NPVO1 | Sin banner | Sin passphrase ni destinatarios; recipient exige private key válida aportada por el usuario |

La contraseña de SSH/proxy/conexión no es la contraseña del archivo y se
conserva. Se conservan parámetros y secciones desconocidas cuando el formato
permite reconstruirlas. Las políticas o variantes no representables se
rechazan para exportación, conservando el descifrado correcto. No se eliminan
silenciosamente expiraciones ni se presume evitar validaciones remotas.
La clave pública de NPV por sí sola no autoriza ni permite recuperar el DEK.
El worker no genera ni retiene una clave privada alternativa.

## API y catálogo

La app nueva envía `X-SPDecode-App-Version: 1.1.21` y
`X-SPDecode-Compatible-Export: 1`. La negociación es una capacidad de protocolo;
la autenticación de sesión, admisión y mantenimiento siguen siendo obligatorias.

El catálogo añade `compatibleExports` solamente cuando hay negociación y
versión >=1.1.21. Su versión proyectada incorpora la revisión de la política;
el watch usa la misma proyección para provocar actualización. Los clientes
anteriores conservan su esquema y versión base. La app consulta capacidad antes
de preparar la exportación y la refresca como máximo cada 15 minutos; la API
comprueba la política actual en cada petición.

Opción aditiva de `POST /api/v1/decode/file`:

```json
{"compatibleExport":{"profile":"original-app-open-v1","language":"es"}}
```

Se añade al cuerpo habitual con `format`, `dataBase64` y las credenciales
necesarias. No hay un endpoint que reemplace la fuente por JSON arbitrario.
Una respuesta correcta mantiene `rawText` y `structuredJson`. Su campo opcional
`compatibleExport` contiene `status: ready`, metadatos fijos, Base64 y SHA-256
del archivo, la fuente y el texto descifrado. Android verifica los tres enlaces,
tamaño, formato, nombre y ausencia de requisitos de apertura antes de guardarlo.
El límite es 1 MiB por artefacto y menos de 6 MiB para la respuesta completa.

Una variante no soportada, timeout o exceso de tamaño devuelve exportación
`unavailable` sin perder el JSON. Desactivar la función o subir la versión mínima
también conserva el descifrado: `EXPORT_DISABLED` o
`EXPORT_CLIENT_UPDATE_REQUIRED`. Pedir explícitamente esta opción sin negociar
el protocolo devuelve 426. Las solicitudes antiguas sin la opción no cambian.
Si la política persistente es ilegible, se desactiva esa preparación con
`EXPORT_POLICY_UNAVAILABLE` y se conserva el JSON. Los controles de sesión y
mantenimiento continúan bloqueando solicitudes como antes.

## Habilitación para pruebas

Después de que el operador actualice por su procedimiento habitual **web y
worker**, aplique la configuración generada de Nginx (65s para `/decode/file`)
y compile/instale la app 1.1.21:

1. Abrir el panel autenticado, sección de sistema, tarjeta **Exportación para
   aplicaciones VPN**.
2. Mantener versión mínima **1.1.21** y activar exportación. Está apagada por
   defecto; el panel persiste el cambio en `provider-control/compatible-export.json`.
3. Importar una muestra propia admitida, revisar su JSON, abrir Exportar y guardar
   la variante compatible. Repetir desde historial después de cerrar/reabrir la app.
4. Importar el archivo guardado en la aplicación original y comprobar edición,
   banner si corresponde y parámetros de conexión. No basta con descifrarlo otra vez.
5. Probar con 1.1.20: debe mantener su catálogo habitual. Subir temporalmente la
   versión mínima a 1.1.22 debe impedir nuevas preparaciones en 1.1.21, manteniendo
   el descifrado. Los artefactos ya guardados siguen siendo archivos del usuario.

Las actualizaciones de política requieren revisión vigente para evitar que dos
administradores se sobrescriban. El interruptor VPS
`CLOUD_COMPATIBLE_EXPORT_LOCKED=true` impide activar desde el panel; está conectado
al compose y a `spdecode config set`. No se ha usado contra un servidor real.

## Verificación y pendientes

Comandos reproducibles sin muestras privadas:

```sh
python -m unittest tests.test_compatible_export tests.test_compatible_export_integration tests.test_cloud_c0_inventory tests.test_cloud_c5_source_isolation tests.test_cloud_history_actions tests.test_cloud_c4_android_bridge -v
python -m unittest discover -s cloud/workers/python -p 'test_*.py' -v
python -m unittest discover -s cloud/infra/vps/tests -v
cd cloud/web
npm install --package-lock=false --ignore-scripts --no-audit --no-fund
npm test
npm run build
```

El workflow `Compatible export 1.1.21 integration` se ejecuta en esta rama y
compila Kotlin Cloud y la instrumentación sintética sin empaquetar APK/AAB.
Las verificaciones de los workflows existentes se actualizaron a 1.1.21/32;
no se activaron sus rutas históricas de publicación ni se cambiaron sus firmantes.
Los nueve archivos de UI congelados C0 conservan sus hashes: Gradle genera
las copias Cloud con el nuevo menú y los manejadores de historial.

Validación local completada: 43 pruebas de exportación/contratos relacionados,
94 regresiones Cloud, 16 del worker, 56 del instalador/controles y 355 Node.
`next build`, ambas tareas de compilación Kotlin y sintaxis JNI/C++ pasan.
La auditoría S.3 del staging final no encontró credenciales ni logs inseguros.
Estas suites comparten algunas comprobaciones; sus cantidades no se suman.

Las pruebas de instrumentación incluidas verifican integridad, asociación con
el resultado y persistencia cifrada. Compilarlas no equivale a ejecutarlas en
un teléfono. El recorrido API → app → selector → app VPN, las ampliaciones con
password/HWID/private key y la apariencia del banner requieren pruebas manuales
con la nueva app. Los resultados previos del laboratorio siguen registrados
en sus informes; no certifican esta integración ni todas las variantes futuras.

Los checkpoints del código y este estado se guardan en la misma rama remota.
Hay también copia local del diff fuera del repositorio; una copia local sola
no garantiza recuperación tras una limpieza del entorno. Ninguna muestra real,
JSON privado, APK original o credencial forma parte de los commits.
