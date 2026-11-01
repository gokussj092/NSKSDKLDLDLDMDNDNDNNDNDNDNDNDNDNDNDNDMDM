# Validación vigente — UT Loop Pro VPN22.10.26/build65

Reinvestigación2026-11-01, sobre22bbdd27 en fix/http-jireh-current-method.
**La descarga OTA firmada real sigue pendiente.**

- **7 Python aprobadas,0 omisiones:**6 UT Loop y1 registro C8. Nuevos casos
  del GET original sin sesión, sesión completa opcional, par incompleto rechazado,
  User-Agent, fuentes/métodos/cuerpo fijo premium, HTML,401,transporte, tamaño,
  codificación, firma obligatoria y diagnóstico sin credenciales/configuraciones.
  Se conservan banners, JDK, CLI, worker, tipos y errores de RSA/GCM/esquema.
- **50 Node aprobadas,0 omisiones:** catálogo, versión/switches persistentes y
  ficha UT Loop todavía desactivada. No se añade allowlist ni transporte Node.
- Original recién descargado:22.10.26/65; base/dex idénticos al análisis previo,
  firmado FC692B18...A1D6. Clave pública RSA idéntica al original.
- Asset real revalidado:1544 bytes,1.0,1 servidor/1 tweak; JSON entero igual a
  Java/JCA independiente, CLI desde /tmp y worker real aislado no parcial.
- **GET real con API key original, sin acceso cacheado**, y **CLI --probe real**:
  HTTP200,text/html,195 bytes,hash5b131ca1...bcd5d7. Ambos devuelven Site Unavailable;
  el CLI sale1 con REMOTE_HTML_RESPONSE y stdout contiene solo diagnóstico.
- No se usaron accesos ficticios contra el servicio. No hay sesión aceptada,
  respuesta OTA/premium firmada real ni evidencia de la causa del HTML.
- No se volvió a llamar nonce/access sin Integrity legítimo. Las denegaciones
  automáticas que citaba la documentación anterior son históricas; no son una
  nueva denegación de herramientas en esta entrega.
- Generador de formatos aprobado, C0240/C8255 conservados. PNG, source59,
  57 fichas y9 remote:null sin cambios. Sin CI manual, fusión, APK ni despliegue.

```bash
PYTHONPATH=. python -m unittest tests.test_ut_loop_pro tests.test_cloud_c8_vpn_registry -v
python scripts/cloud_formats_catalog.py
# Una petición real fija; no muestra datos privados del catálogo.
python decoders/Python/apps/UT_Loop_Pro_VPN/server_catalog_decoder.py --probe
cd cloud/web
node --test tests/server-vpn-catalog.test.mjs tests/server-vpn-version-sync.test.mjs tests/c12-provider-controls.test.mjs
```

El User-Agent predeterminado del CLI es un prefijo Dalvik, no la identidad exacta
de un teléfono. UT_LOOP_USER_AGENT admite el valor real de una instalación propia.
Los tests usan un firmante sintético solo dentro del test; producción conserva
su clave RSA original y nunca acepta ese firmante de pruebas.

Recuperación, hashes completos, flujo de renovación y próximo requisito real
en el [handoff](../../../../docs/cloud/UT_LOOP_PRO_REINVESTIGACION_2026_11_01.md).

---

## Evidencia histórica2026-10-22 (la exigencia incondicional de sesión fue corregida)

# Validación — UT Loop Pro VPN 22.10.26

2026-10-22, base del PR #96: `cf10003bc11b745501fd69d3117676258ef58887`.

## Comprobaciones puntuales

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_ut_loop_pro -v
cd cloud/web
node --test tests/server-vpn-catalog.test.mjs tests/server-vpn-version-sync.test.mjs tests/c12-provider-controls.test.mjs
```

**4 pruebas Python y 38 pruebas web aprobadas**, sin suites completas del proyecto.
Python cubre documento JDK completo, CLI desde fuera del repositorio, bridge y
subproceso aislado real; firma RSA correcta con clave sintética limitada al test,
rechazo del firmante sintético por producción, cambios de firma/tag, esquema,
JSON duplicado, HTML, límites y falta de credenciales. Comprueba banners GCM de
ambos certificados y XXTEA contra JDK, CLI auxiliar y errores. El transporte
remoto controlado comprueba método, URL, cabeceras, cuerpo premium y rechazo de
redirecciones; no genera accesos oficiales.

Las pruebas web comprueban la ficha, el SHA-256 exacto del PNG, versión/conteo y
que el proveedor no pueda descargarse ni habilitarse mediante un override de
la disponibilidad. Se mantienen las fichas y allowlists anteriores.

## Muestra real aportada

- APK base SHA-256 `8df86b9839e7fd77463081cea983136c8c6684a2506777d622b7e4cea965abb8`.
- Catálogo inicial: 1544 caracteres Base64, SHA-256
  `23c3f897d17646bd610db2d253da8dcbe413ea29b7997123457ed175ed8bcb15`.
- Versión **1.0**, **un servidor / un tweak**; GCM autentica el contenido completo.
  Todo el JSON, no solo los recuentos, coincide con el JDK independiente, CLI
  stdin ejecutado fuera del repo y worker aislado; salida de 1174 bytes,
  `isPartial:false`. La clave pública RSA coincide byte por byte con el APK.
- El catálogo inicial sin envoltura RSA no demuestra haber validado una firma
  de producción. Las respuestas remotas firmadas solo tienen cobertura sintética.
- No se publica la muestra cifrada/descifrada ni valores reales de configuración.

## Referencia independiente

`tests/golden/ut_loop_pro_oracle.java` usa JCA, las constantes originales y una
transcripción separada de XXTEA; no importa el lector Python. El generador
`ut_loop_pro_generate.py` produce vectores sintéticos con claves de prueba,
registros repetidos, tipos/nulos/listas, metadatos desconocidos y todos los
campos de protocolos representativos. La clave privada sintética se genera solo
dentro del proceso JDK y no es una clave de la app. Producción no ofrece una
opción para sustituir su clave de verificación. El generador requiere Java 17+
con capacidad de ejecutar archivos fuente.

## Límite remoto observado

Consulta real autorizada del catálogo fijo: HTTP **200**, `text/html`, **195
bytes**, SHA-256 `5b131ca14aa96311d3432b0062c7443d3b0e6346ec279bd376a75f0a76bcd5d7`,
texto `Site Unavailable`. No es un catálogo exitoso ni prueba de caída global.
Faltan respuesta OTA firmada real, acceso oficial aceptado y respuesta premium
real. Los chequeos adicionales de acceso fueron bloqueados por revisión
automática, no se reintentaron y no aportan evidencia. No se afirma paridad de
un catálogo remoto, sesión VPN, ejecución Android, exportación real de perfiles,
éxito CI remoto, despliegue VPS ni publicación de la APK.
