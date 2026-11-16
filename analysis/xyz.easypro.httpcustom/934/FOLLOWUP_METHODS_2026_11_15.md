# Seguimiento del original: HC2/RSA y derivación n16

Estado del descifrado de los nueve archivos: **6/9**, sin éxitos nuevos en
n16, n18 o wrapper 9. Este seguimiento añade primitivas y evidencia, no
presenta los tres métodos completos como resueltos.

## Componentes implementados y comprobados

1. **Cálculo HC2 real:** el ID del certificado público de la muestra coincide
   con `HC2-` + Base64url sin padding de SHA-256 del DER **SubjectPublicKeyInfo**.
   El hash del DER PKCS#1 es distinto. `tools/hc2_identity.py` genera RSA-2048,
   privada PKCS#8, pública DER e ID con este cálculo. Siempre declara
   `UNREGISTERED`, sin certificado de emisor ni activación inventados. Un par
   nuevo no abre archivos dirigidos al anterior.
2. **Perfil RSA del original:** se ejecutó el inicializador de
   `dev/epro/r0/E5538123785991428492`, registrado por dispatcher 0, índice 858.
   Se observaron los argumentos originales de OAEPParameterSpec:
   SHA-256, MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT. El mismo
   inicializador construye PSSParameterSpec SHA-256/MGF1-SHA256, saltLen 32 y
   trailer 1. El recorrido completo de wrapper 9 hasta esa clase no está
   contrastado con una privada original: **no se certifica descifrado del
   archivo ni firma del certificado**.
3. **Unwrap RSA implementado:** `unwrap_header()` selecciona destinatario por
   pública/ID, exige privada correspondiente y aplica el perfil OAEP observado.
   Se contrastó con un oráculo independiente JCE/Java 21 y datos sintéticos.
   Pública sola, otra privada, MGF1-SHA256 y ciphertext alterado se rechazan.
   Devuelve explícitamente `issuer_signature_verified=false` y
   `payload_decrypted=false`: la operación RSA aislada no certifica el JSON HC.

Uso reproducible de las primitivas; mantener los materiales privados fuera
del checkout:

```sh
python analysis/xyz.easypro.httpcustom/934/tools/hc2_identity.py generate /privado/nueva-identidad
python analysis/xyz.easypro.httpcustom/934/tools/hc2_identity.py unwrap /privado/acceso.hc /privado/privada-correspondiente.pem /privado/clave-contenido.bin
python -m unittest discover -s analysis/xyz.easypro.httpcustom/934/tests -v
```

El segundo comando requiere la privada real correspondiente; generarla de
nuevo no satisface ese requisito. La raíz/emisor del certificado y la apertura
de todas las secciones del wrapper 9 siguen pendientes. No se usa el unwrap
como prueba de identidad de un emisor ni como sustituto de activación.

## Recorrido n16 recuperado

Se inspeccionaron los cuatro DEX originales con Androguard 4.1.3. La firma
real de `N640...c` incluye password-key, schedule, HWID y un flag de sesión.
Al suministrar **datos sintéticos explícitos** se observó la ruta original:

`c(n16, session=true)` → `d(family=5)` → `Z165...a` → `T111...q` con
**operación 2, familia 5**. Sus arrays contienen HWID, seed de 32 bytes,
info vacío, password-key de 32 bytes y material adicional vacío.
La ruta sin el flag de sesión usa operación 1. No son intercambiables.

Se conservaron dos hipótesis nuevas para clave de contenido y doce de wrap
de familia 5; ninguna autentica la muestra n16. No se enumeraron contraseñas,
HWIDs ni claves: se usaron exclusivamente los datos aportados y dos formas
de normalización. Esto no demuestra que las credenciales sean incorrectas.

### Mejoras y límites del entorno nativo

- Se corrigió el stub `lrand48`, que devolvía siempre cero, por el LCG POSIX
  de 48 bits. Sus seis primeras salidas coinciden con libc independiente.
- El inicializador RSA se completó modelando objetos JVM públicos, boxing,
  arrays y constructores; los parámetros fueron recuperados del original.
- La traza de `q` se amplió con límites de control de flujo, syscalls acotadas
  de entropía, asignaciones virtuales y un directorio Android **solo en memoria**.
  No se ejecutan bibliotecas Android en el proceso anfitrión ni se leen datos
  de otra instalación. La memoria virtual no se trata como estado original.
- Se modeló únicamente información pública de paquete/certificado y la
  superficie Binder de consulta de paquetes. Los experimentos con el callback
  local sustituido por 0/1 son **diagnósticos sintéticos**, no una atestación
  ni una activación válida. No se contactó ningún servicio externo.
- La operación 2 todavía devuelve null en ese modelo incompleto. No se obtuvo
  una clave ni un oráculo que autentique n16. Ni la inicialización con retorno
  cero ni la ausencia de un crash se presentan como éxito criptográfico.

Herramientas retenidas: `dex_followup.py`, `native_followup.py`,
`trace_native_q.py`, `native_memory_fs.py`, `trace_oaep_init.py`,
`access_followup.py`, `probe_n16_content.py`, `probe_n16_wrap_family5.py` y las
extensiones de `probe_kdf.py`/`jni_format_probe.py`.

Recetas sin credenciales en argv; `auth.json` se mantiene privado:

```sh
python analysis/xyz.easypro.httpcustom/934/tools/access_followup.py /privado/acceso.hc
python analysis/xyz.easypro.httpcustom/934/tools/dex_followup.py /privado/934/base.apk
python analysis/xyz.easypro.httpcustom/934/tools/trace_oaep_init.py /privado/934/libf2c-initialized.so
python analysis/xyz.easypro.httpcustom/934/tools/probe_kdf.py /privado/934/libf2c-initialized.so /privado/n16.json --entry c --schedule n16 --synthetic-hwid --synthetic-password-key --session
python analysis/xyz.easypro.httpcustom/934/tools/probe_kdf.py /privado/934/libf2c-initialized.so /privado/provider.json --entry provider --family 5 --session
python analysis/xyz.easypro.httpcustom/934/tools/probe_n16_content.py /privado/HttpCustom_934_revisado.py /privado/muestras < /privado/auth.json
python analysis/xyz.easypro.httpcustom/934/tools/probe_n16_wrap_family5.py /privado/HttpCustom_934_revisado.py /privado/muestras < /privado/auth.json
python analysis/xyz.easypro.httpcustom/934/tools/trace_native_q.py /privado/934/libruntime-initialized.so --operation 2 --family 5 --family5-inputs --model-local-risk-clean --risk-model-value 1 --public-certificate /privado/934/certificate.der
```

Los experimentos previos, fallos significativos y límites se conservan en los
scripts y en el checkpoint anterior; binarios, cachés y logs íntegros quedan
privados. Las pruebas no usaron dispositivos físicos, ADB, activación remota
ni una privada de la instalación original.

## Protección extra n18

El exterior autenticado de `Test hwid.hc` contiene `p.a` de 14 caracteres,
`p.b` Base64 de **384 bytes** y `p.c` Base64 de **32 bytes**, además de un slot
HWID. El tamaño de 384 bytes es compatible con un bloque RSA-3072, pero esa
identificación por tamaño **no prueba** algoritmo, unwrap ni contenido.
La documentación oficial requiere activación inicial autorizada; no se
dispone de su respuesta/caché original ni se ha recuperado el formato interior.
No se genera una respuesta falsa ni se anuncia soporte offline de n18.

## Estado y siguiente evidencia necesaria

- n16: falta reproducir una derivación que autentique slot y todas las capas.
- wrapper 9: falta la operación legítima de la privada destinataria y validar
  el recorrido de unwrap/AAD/secciones y el certificado del emisor.
- n18: falta observar la activación autorizada y su material original, además
  de autenticar el interior. El código del cliente no sustituye ese estado.

No se cambió el lector operativo, servidor, Android ni main. HMAC de archivo
n15 sigue contrastado; transporte VPN no ejecutado; autenticación de conexión
permanece **UNCONFIRMED**, sin extracción de secretos de servicios.

## Verificación del seguimiento

- 14/14 tests del expediente, incluido el oráculo JCE independiente.
- 29/29 regresiones existentes del lector y su puente Cloud.
- Sintaxis Python, JSON y `git diff --check`: correctos.
- Gate F7 de estructura de evidencia: correcto; no aprueba el método pendiente
  ni habilita n16/n18/wrapper 9 en producción.

## Reanudación tras la interrupción del chat

El checkpoint `86d8be9c` quedó publicado y el checkout no tenía cambios sin
guardar ni procesos pendientes. Se retomó únicamente el diagnóstico de n16.

Se corrigió la lectura de FP/LR en `Probe.reg()`: Unicorn identifica X29 y
X30 fuera del intervalo numérico X0–X28. La expresión anterior X0+30 leía
otro registro e imprimía direcciones de retorno incorrectas en ciertos logs.
No cambia la derivación ni convierte un resultado null en una clave. El
emulador compartido y el lector operativo no se modifican.

`trace_native_q.py --diagnostics` conserva ahora hasta 64 bloques recientes,
conteos de imports modelados y hasta 128 eventos de filesystem por fase.
No imprime buffers, HWID, contraseñas, claves ni nombres de archivos locales.
La nueva ejecución, con los mismos **datos sintéticos**, observó:

- Contexto público: el directorio virtual existe; `openat` intenta leer un
  archivo relativo de cuatro caracteres y recibe ENOENT. El retorno de la
  llamada original está en `0x134a74`. En una inspección privada se identificó
  el nombre fijo del original `.s31`; no se leyó ni fabricó su contenido.
- Operación 2/familia 5: devuelve null y no hace otras llamadas de filesystem.
- La ausencia del archivo **no prueba por sí sola la causa** del null ni
  determina su contenido. Tampoco prueba contraseña/HWID incorrectos.
- El inicializador público de alto nivel se detiene además en
  `Looper.getMainLooper()`, que el modelo no implementa. La llamada directa
  al inicializador de runtime no reproduce el ciclo de vida completo de la app.

Las 16 pruebas actuales del expediente pasan, incluidas dos nuevas que
contrastan FP/LR y los registros de argumentos con Unicorn directamente.
El resultado real permanece **6/9**, con los mismos tres métodos pendientes.
La próxima comparación útil exige observar una importación autorizada en
la instalación original, manteniendo su privada y activación en el dispositivo.
