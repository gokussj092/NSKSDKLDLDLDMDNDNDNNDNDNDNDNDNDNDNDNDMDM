# HTTP Custom 8.0.22 Patch 2 / 934 — investigación pendiente

## Identidad e insumos

Archivo APKS y nueve exportaciones aportados por el propietario para probar
SP-DECODE con sus credenciales. El manifiesto binario del base identifica
`xyz.easypro.httpcustom`, versionCode 934, versión `8.0.22 - Patch 2`.
Los splits ARM64 y xhdpi también declaran 934. Inventario y SHA-256 completos
en `generated/inventory.json`. El certificado extraído del bloque de firma
tiene el mismo SHA-256 observado en 899/914. No se ejecutó apksigner ni se
certifica aquí la verificación criptográfica completa de la firma APK.

No se versionan APKS, SO, perfiles, credenciales, certificados de destinatarios,
envelopes privados, claves de sesión ni JSON descifrados.

## Observaciones reales

- Los **9/9 HCX4 exteriores autentican** con el lector existente. Esto permite
  inventariar el envelope, pero no significa que se hayan descifrado perfiles.
- Siete muestras son HCCFG 12: seis n15 y una n16. Dos n15 llevan contraseña;
  la n16 combina contraseña y slots HWID. Cada una declara dos secciones `j`.
- Una muestra es HCCFG 13/n18, tiene un slot HWID y `p.a/b/c` de protección
  extra. No es el mismo formato que la muestra n16 sin protección extra.
- El archivo de ID de acceso usa un wrapper HCCFG 9, cuyo `c` codifica un
  objeto con header y secciones. El header contiene un certificado público
  firmado por destinatario y una clave envuelta de 256 bytes. Su RSA pública
  es de 2048 bits; no contiene una clave privada. La firma del certificado
  mide 384 bytes, pero **no se verificó su firma**. El ID del certificado
  coincide con el ID aportado por el propietario. El ID es un identificador
  público; no permite por sí solo realizar el unwrap RSA del destinatario.
- El lector actual termina `UNSUPPORTED_SCHEMA` en los nueve. El worker
  devuelve `DECODE_FAILED`, sin salida parcial. Resultados reproducibles en
  `generated/real_validation.json`.
- GET y HEAD anónimos al enlace Cloud aportado responden HTTP 200; el GET
  devuelve HTML de instrucciones para abrirlo en HTTP Custom, no bytes .hc.
  No se dedujo de ello que el enlace estuviera caducado o fuera inaccesible.

## Contraste local del original y límites

JADX 1.5.3 terminó con 55 errores generales; permitió identificar firmas,
no certificar una descompilación completa del código protegido.

Se usaron los scripts conservados en `tools/` para inicializadores ELF,
registros JNI y trazas de funciones aisladas con **entradas sintéticas**.
Los preámbulos locales de integridad se redirigieron únicamente en memoria
de Unicorn: 348 en runtime y 111 en f2c. No se modificó ningún APK ni se
emitió una atestación o activación ante un servicio.

Registros observados en el modelo local:

- `N6400668577528756650.c/d`, `0xaa779c/0xc1b598`, forman transcript/info
  similares a los anteriores y entregan material a una interfaz de claves.
- `Z16537246539122903131.a`, `0xcf6470`, delega a
  `T11126252552580400142.q`, firma `(IJJ[[B)[B`.
- `L13637848319454070128` representa sesiones/handles de clave nativos.
- El accessor f2c `0xdcbd48` produjo 835 cadenas estáticas; el índice siguiente
  se rechazó. Sus valores completos quedan privados.

La simulación parcial de `c` con n15 llegó a familia 1 y n11 a familia 4.
La operación nativa sintética observada fue `q(1, 0, familia, arrays)`.
**Esto no acredita la KDF real de una importación ni su clave final**: los
campos estáticos y numerosas llamadas Android están modelados, no ejecutados
en Android. La ruta original completa de inicialización alcanza Looper,
Binder y comprobaciones de entorno. Las llamadas desconocidas detienen el
probe; una prueba nativa se interrumpió al permanecer en inicialización.
No se obtuvo un oráculo de cifrado/descifrado nuevo. No hay ADB, emulador
Android ni `/dev/kvm` en el entorno disponible.

La búsqueda estática localizó una constante histórica C0 en runtime, pero
sus referencias y tablas de saltos no permitieron identificar una KDF nueva
verificada. La presencia de una constante antigua no acredita compatibilidad.

Se contrastaron dos hipótesis acotadas con la contraseña/HWID aportados:
reutilizar `native_fold` de 899 o `_c0` histórico, conservando transcript,
HKDF y cambiando etiquetas a esquema/schedule nuevo. Ambas fallan la
autenticación en las siete muestras HCCFG 12. La comprobación diagnóstica
de flujo tampoco produjo estructura JSON; jamás se devolvió como resultado
descifrado. No se buscaron contraseñas ni se enumeraron claves.

## HMAC y autenticación

| Ámbito | Resultado |
| --- | --- |
| Archivo | HCX4 exterior autenticado. HMAC/HKDF del lector anterior conocido; nueva sesión interior pendiente. |
| Transporte VPN | No ejecutado; presencia de bibliotecas no demuestra un MAC de autenticación. |
| Autenticación de conexión | UNCONFIRMED; sin conexiones VPN ni extracción de secretos de servicios. |
| Protección extra | Documentación oficial describe activación inicial y reutilización en el mismo dispositivo; no se obtuvo un grant ni se observó activación. |

Referencia primaria consultada: https://eprodev.org/api/ (apartados Access ID y
Extra Protection). La API de creación no se trató como API de descifrado.

## Siguiente evidencia necesaria

Contrastar una importación legítima del original con el flujo nativo completo,
resolver la derivación de sesión y autenticar **todas** las secciones antes
de habilitar n15/n16. Para el wrapper de acceso se necesita la operación
legítima de la clave privada del destinatario, no su ID público. Para n18
con `p` falta la evidencia de activación original y su caché/grant autorizado.
El protocolo real de descarga eprdv.link sigue sin caracterizar.
