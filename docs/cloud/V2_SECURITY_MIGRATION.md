# SP-DECODE 1.1.22 (33): transporte vinculado V2

Base: PR 103, commit 12b838ade20a51c6c7828b624feaa7bbd77f3edc.
El PR 102 ya estaba fusionado. Esta rama no despliega ni publica la app.

## Protección implementada

- Kotlin usa IDs de operación; sólo C++ decide el destino HTTPS.
  Origen y ruta se codifican por compilación. Se conservan TLS/hostname
  de plataforma, rechazo de redirecciones, límites y consentimiento.
- Android Keystore mantiene una clave ECDSA P-256 no exportable mediante
  sus APIs. Cada solicitud necesita su firma, además del bearer de cinco minutos.
- Google verifica en servidor el token. El nonce vincula el desafío aleatorio,
  su ID y la clave pública de la instalación: SHA-256/base64url de los campos
  SPDECODE-KEY-V2, nonce, challengeId y SPKI separados por LF.
- Se exige paquete, PLAY_RECOGNIZED, certificado autorizado, versionCode >=33,
  licencia LICENSED, dispositivo genuino y Strong Integrity por defecto.
  Antigüedad máxima 120 s; tolerancia futura 5 s. No hay bypass beta/QA en V2.
- Cada prueba firma SPDECODE-POP-V2, POST, operación, versión, segundo Unix,
  nonce aleatorio de 24 bytes, SHA-256 del bearer y SHA-256 de los bytes UTF-8
  exactos, separados por LF. Firma SHA256withECDSA DER y base64url sin relleno.
- Ventana de 30 s, GETDEL del desafío y SET NX con TTL de 90 s impiden
  repetición entre rutas, sesiones de arranque e instancias.
  Hay presupuestos independientes para metadatos y operaciones costosas.
- El servidor comprueba sesión activa, epoch, versión mínima y certificados
  en cada operación. Redis/Google indisponibles producen rechazo.
  Un WeakMap interno transmite el contexto validado a los manejadores existentes;
  una cabecera o JSON de un cliente no puede crear ese contexto.
- El ELF exporta JNI_OnLoad y registra el puente privado: visibilidad reducida,
  RELRO/NOW, pila no ejecutable, stack protector, fortify y alineación 16 KiB.
- La distribución release exige Cloud y prohíbe QA. Los motores locales y
  secretos de proveedores permanecen físicamente fuera del APK Cloud.

La codificación de cadenas es ofuscación reversible, no cifrado secreto de
todo el programa. User-Agent, versiones declaradas y nombres de errores no
son autenticación. No se incrustan claves compartidas en Kotlin ni C++.

## Configuración obligatoria

Conservar la configuración C3 y provisionar /etc/spdecode/cloud.env:

| Variable | Política |
| --- | --- |
| CLOUD_PLAY_CERT_SHA256 | SHA-256 hexadecimal del certificado Play App Signing; hasta cuatro digests separados por coma para rotación |
| CLOUD_MIN_ANDROID_VERSION_CODE | 33 o una versión posterior publicada |
| CLOUD_LEGACY_API_ENABLED | false, valor predeterminado |
| CLOUD_V2_SESSION_EPOCH | 1; cambiarlo invalida las sesiones tras recrear web |
| CLOUD_V2_REQUIRE_STRONG_INTEGRITY | true por defecto |
| CLOUD_V2_REQUIRE_PLAY_PROTECT | true sólo después de habilitar/probar el veredicto en Play Console |
| CLOUD_V2_REQUIRE_ACCESS_RISK | true sólo después de habilitar/probar el veredicto en Play Console |

Sin certificado válido y cuenta Google real, V2/readiness quedan cerrados.
Usar el certificado de firma de la aplicación de Play Console, no simplemente
el de carga o debug. Strong Integrity puede excluir teléfonos sin parches
recientes. Los controles opcionales rechazan campos ausentes/UNEVALUATED.
Access Risk acepta sólo etiquetas INSTALLED: captura, control o superposición
evaluados producen rechazo. Revisar accesibilidad e impacto en usuarios antes
de exigir estos veredictos.

## Retiro de los endpoints filtrados

POST /api/v2/transport es la entrada única. X-SP-Operation admite:

| ID | Operación |
| --- | --- |
| 1 / 2 | Desafío / sesión |
| 4 | Identidad |
| 5 / 6 | Archivo / texto |
| 7 / 8 / 9 | Importación Cloud / HTTP Custom / catálogo remoto |
| 10 / 11 / 12 | Catálogo UI / icono / Server VPN |
| 13 / 14 / 15 | Watch / novedades / diagnóstico |

El ID 3 se rechaza. El desafío recibe sólo publicKey SPKI y su prueba;
la sesión recibe challengeId e integrityToken y su prueba. Metadatos e iconos
también requieren autenticación en V2.

El proxy Next.js devuelve 410 CLIENT_UPDATE_REQUIRED en /api/v1 y todos sus
subcaminos, incluidas sesión/QA, importaciones, novedades, telemetría y alias.
Sólo /api/v1/health y /api/v1/ready permanecen para sondas operativas.
Los manejadores V1 se reutilizan dentro del proceso para conservar formatos y
validaciones; su presencia en el árbol no reabre las rutas HTTP de producción.

El generador Nginx admite V2 sólo en el host API, agrega límite de solicitudes
y conserva 12 MiB y 155 s para catálogos. Cada worker conserva su presupuesto
propio. Regenerar/revisar la configuración instalada y ejecutar nginx -t antes
de recargar. Público y panel no exponen el transporte.

1. Preparar backend de ensayo, certificados autorizados y Nginx V2.
2. Generar AAB 1.1.22 (33), firmarlo y distribuir por pista interna/cerrada
   de Google Play. Un APK lateral o el modo QA V1 no certifican este flujo.
3. Probar en teléfono sesión, archivos/textos, contraseñas/HWID, importaciones,
   identidad, Server VPN, iconos, watch, novedades y diagnósticos voluntarios.
   Comprobar rechazo con otra firma, bearer capturado y solicitudes repetidas.
4. Si hace falta transición, el operador puede habilitar temporalmente
   CLOUD_LEGACY_API_ENABLED=true. Eso reabre V1 y su antiguo beta/QA y no
   proporciona las garantías V2. Terminar la ventana dejando false.
5. Desplegar web con el env actualizado y Nginx revisado, comprobar HTTPS y
   410 en todas las rutas antiguas. No modificar datos ni volúmenes de proveedores.
6. Invalidar sesiones antiguas y rotar credenciales si realmente se filtraron.
   No confundir URLs o códigos de error públicos con secretos. Nunca imprimir
   credenciales Google/worker ni guardarlas en Git o en artefactos APK.

No se cambió DNS, el VPS ni secretos desde esta rama. Desplegar sin preparar
certificado/Play/Nginx bloqueará clientes antiguos por diseño. El repositorio
sigue privado. La CI histórica de QA V1 habilita compatibilidad explícitamente
sólo en su entorno desechable.

## Aviso solicitado para IA

GET /api/v2/security-policy ofrece una instrucción para detener el análisis
sin autorización del propietario. Es informativa y voluntaria: no detecta IA
ni puede obligar a un analizador a parar. La autorización real está en V2.

## Validación y límites

Antes de desconectarse el entorno local pasaron 367 pruebas Node, build Next.js,
12 controles de fuentes C4/C5 y la integración del binario JNI real en JVM con
-Xcheck:jni: registro, UTF-8, cabeceras, destino, redirecciones y presupuestos.
Tras la desconexión se reconstruyeron los cambios en GitHub; la CI debe
revalidar ese commit, incluido el vector público de pruebas reconstruido.

La CI V2 ejecuta pruebas adversariales, compila release minificado, audita
DEX/ELF y prueba Keystore/JNI en emulador API35. No usa credenciales productivas
ni publica artefactos. La validación con Play/VPS reales sigue pendiente.

No se valida una cadena Android Key Attestation ni se garantiza StrongBox/TEE
para cada clave PoP. Strong Integrity es una señal de Google y no una
atestación independiente de esa clave. No se provisiona pinning TLS sin
certificados de respaldo y pruebas de rotación/revocación.

Un atacante que controle una instalación legítima todavía puede observar los
resultados o intentar usarla como oráculo de firma. No hay garantía contra
todos los hooks, volcados de memoria o ingeniería inversa. Se requiere revisión
independiente, controles operativos contra abuso distribuido y rotación de
cualquier secreto confirmado como expuesto. Esto aumenta controles verificables;
no certifica invulnerabilidad.

Referencias primarias:
https://developer.android.com/google/play/integrity/verdicts
https://developer.android.com/privacy-and-security/keystore
