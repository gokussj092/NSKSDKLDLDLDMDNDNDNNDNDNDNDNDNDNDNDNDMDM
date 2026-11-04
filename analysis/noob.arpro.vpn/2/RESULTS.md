# Resultado: PENDING remoto / PARTIAL investigación

**NETWORK_UNAVAILABLE_IN_THIS_ENVIRONMENT:** ambas URLs de catálogo observadas
devuelven HTTP200 con195bytes HTML «Site Unavailable». SHA256 idéntico:
`5b131ca14aa96311d3432b0062c7443d3b0e6346ec279bd376a75f0a76bcd5d7`.
No hay JSON remoto completo verificado ni integración activa. No se puede
concluir de esta respuesta que el proveedor esté caído para todos sus usuarios.

**OBSERVED_INCLUDED_ONLY:** recurso noobdev.js de la APK fijada abierto mediante
la operación XTS observada en el nativo:1 servidor/1 tweak. Tres metadatos GCM
autenticados: Version1.0.0, DefUpdateURL y updater. No se certifican los registros
completos, XTS independiente, exportación, archivos ni texto. Se conservan
scripts de recuperación, offsets, hashes y limitaciones para continuar después.

**VERIFIED_RESEARCH_CHECKS:**5/5 comprobaciones locales: dos literales del build
contrastados con JDK Random, rechazo de HTML200 como catálogo, clasificación
conservadora de bytes desconocidos, límites/estados, Base64 inválido y redirects.
No se presentan como pruebas de un descifrador remoto funcional. `verify_pending.py`
reproduce el alcance limitado con los originales privados y rechaza certificarlo.

Metadatos de actualización Pastebin: HTTP200/JSON3436bytes, package encontrado;
no se sigue ningún enlace de APK/artefacto. JADX1.5.6 exit3/38 errores; primary
DEX analizado, secondary inventariado. La lectura inicial de res/raw/noobdev sin
extensión falló; se corrigió al recurso real .js. No se omiten estos límites.

Solo documentación/herramientas de investigación en analysis/. Sin cambios en
decodificadores, broker, worker, catálogo, secretos, Android o workflows.
Sin compilaciones ni espera de artefactos, merge o despliegue. No se ejecuta
APK/JNI/SO. Estado y pruebas guardados en MANIFEST/generated. Licencias
transitivas y reutilización Fase7 pendientes de revisión; CI de evidencias
sigue sin implementarse. APK, datos reales, constantes nativas y respuestas
privadas no entran en Git; solo la página HTML pública de error es fixture.
