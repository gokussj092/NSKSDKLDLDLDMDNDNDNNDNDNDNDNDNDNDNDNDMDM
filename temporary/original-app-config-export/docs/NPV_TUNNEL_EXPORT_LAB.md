# NPV Tunnel: NPVO1 abierto y reencriptación NPVS v5

Fecha: 2026-10-27, America/Tijuana. Misma rama temporal y cuenta Goku.
Solo se añaden herramientas al laboratorio; el lector productivo, Android,
API, otras aplicaciones y VPS no se modifican.

## Material y punto de partida

Aplicación suministrada: **NPV Tunnel 124.0.37, build 577**,
`com.napsternetlabs.napsternetv`. El lector existente
`decoders/Python/npvs.py` abre la muestra protegida completa, sin contraseña
ni clave de destinatario. No fue necesario corregirlo ni extraer otra vez
sus tablas white-box.

| Muestra privada | Bytes | Formato | SHA-256 |
| --- | ---: | --- | --- |
| Referencia abierta aportada | 524 | `NPVO1\n` + JSON | `7a5768a4bcf555b4a01f7f3200665ec087f259ef6855dad539752cfd06c46a36` |
| Referencia protegida aportada | 1622 | NPVS v5 / app-key 2 / keyId 2 / cero destinatarios | `160e63ac51279f8576ba25bed5b26a34a99b2dafd3a99a8fb2673c306f1fce30` |

Ambas contienen un perfil V2Ray, pero **son conexiones distintas**. No se
copian servidores, puertos, contraseñas ni opciones entre ellas. La protegida
contiene 20 registros autenticados: 19 escalares y el layout. Su política
contiene `configVersion:2`, `onlyMobileNetwork:false`, `attestationLevel:"NONE"`,
`expiresAt:null` y los dos mensajes vacíos. Esto no demuestra que su editor
esté abierto: el tipo de contenedor participa en la importación.

Los datos y APK originales, JSON privados, bibliotecas y documentos de conexión
quedan fuera de GitHub y de los logs. El ZIP privado incluye solamente los
archivos de prueba, instrucciones y reportes sin secretos; tampoco incluye APK
ni claves privadas de firma.

## Evidencia de la aplicación original

El APK base recibido tiene SHA-256
`1999c5748b1ab1cc9a314573052665c96619cdd3bef570704e778ad5b5901a74`.
Las bibliotecas ARM64 coinciden exactamente con las ya investigadas:

- `libgojni.so`: `ea5c68f088256b648b91c0ca009ad7f6d144e5d107608f622a5f564c9bc8891b`.
- `libnpvtunnel.so`: `6ba05d3ac27f28b1b058b1162c0c0de0009fff47fc876b7e924f3288b1fd7c89`.

`probe_npvs_apk.py` exige esos hashes y comprueba directamente los operandos
DEX de los métodos auditados. No ejecuta la aplicación ni necesita JADX.
La inspección adicional con JADX 1.5.6 terminó con 266 errores globales;
no se presenta como una decompilación completa. Se pudieron revisar estas rutas:

- `uh.t4.o` elimina `NPVO1\n`/`NPVO1`, carga `ah.h0` (`ConfigBodyList`) y
  transforma sus perfiles mediante `ah.r2.e`. Construye `fh.y` con el flag
  de bloqueo falso. Es una ruta de importación abierta observada, no un flag
  JSON nuevo inventado por el exportador.
- `ah.r2.g`, usado por la importación protegida, construye `fh.y` con el flag
  de bloqueo verdadero. Cambiar solo una política vacía no convierte de forma
  demostrada un contenedor NPVS en uno editable.
- `ah.f0` declara `configs`; `ah.c0` declara `name`, `address`, `type`,
  `v2rayProfile`, `sshConfig`, `message` y `customServerMessage`.
- `ah.k3` es el serializador `SecretString`: acepta y emite `npvs1:` seguido
  de Base64. Esos tokens también están presentes en la referencia abierta.
  No deben eliminarse ni confundirse con un fallo de descifrado.

Estas son comprobaciones estáticas. Al generar la tanda, importación, edición
y conexión estaban pendientes. El reporte manual posterior de abajo actualiza
la importación, sin convertir las comprobaciones estáticas en ejecución Android.

## Sin banner

Se respeta la instrucción de no añadirlo en esta fase. El APK tiene campos de
mensajes de texto, pero eso no acredita soporte HTML ni un banner equivalente
al de HTTP Custom/Injector. No se insertan mensajes, créditos, URLs ni flags
en ninguno de los cinco casos. No se afirma que la aplicación sea incapaz de
mostrar notas; simplemente no se prueba esa función aquí.

## Preservación y reconstrucción criptográfica

`npvs_export_experiment.py` autentica el archivo mediante el lector existente
y conserva **cada plaintext de registro**, su identificador, el layout y los
bytes JSON de los metadatos. Reconstruye el documento sustituyendo solamente
las referencias de escalares por sus tokens originales. Mantiene orden,
espacios, escapes, notación numérica, tipos, secciones desconocidas y `npvs1:`.
No utiliza el texto presentado al usuario ni el JSON normalizado por
`decode_npvs_complete` como sustituto de la fuente original.

La reencriptación v5 usa un nuevo configId, una nueva pareja P-256 de firma,
DEK, sal app-key, nonce de wrapping y nonce de metadatos. No se dispone de la
privada del creador original y **no se simula su firma**. Se conserva el
`issuedAt` original dentro de los metadatos; la nueva firma representa una
exportación del laboratorio, no la identidad del exportador anterior.

Se reconstruyen:

1. KDK app-key mediante el evaluador white-box existente y el nuevo configId.
2. Wrapping ChaCha20-Poly1305 de la DEK, con sal como AAD.
3. Metadatos, clave HKDF `NPVS-v5/metadata`, cabecera compacta como AAD.
4. Contexto de documento unido a creator, configId, política, fecha y nonce.
5. Cada registro ChaCha20-Poly1305 con su clave HKDF e identificador. El nonce
   cero por registro pertenece al esquema observado; la nueva DEK/contexto
   produce claves nuevas, distintas por identificador.
6. Inventario HMAC-SHA256, longitudes BE, firma ECDSA P-256/SHA-256 en formato
   P1363 de 64 bytes y EOF exacto.

El lector productivo verifica nuevamente todo el resultado. Un segundo
verificador usa cryptography/OpenSSL, HKDF por HMAC y un parser independiente;
además se ejecutó el verificador JDK ya existente sobre los tres contenedores
cifrados del paquete. Los verificadores comparten el evaluador white-box
previamente contrastado con el ARM64 original; esa pieza no constituye un
segundo backend independiente en esta sesión. Sus tres vectores nativos
existentes vuelven a pasar y los hashes de las bibliotecas coinciden.

## Cinco archivos para probar

| Archivo | Propósito y resultado local |
| --- | --- |
| `A_OPEN_ORIGINAL.npvs` | Copia idéntica de la referencia abierta; control NPVO1 |
| `B_PROTECTED_ORIGINAL.npvs` | Copia idéntica de la protegida; control NPVS |
| `C_PROTECTED_REENCRYPTED.npvs` | Nueva criptografía y firma v5; documento, metadatos y registros originales intactos |
| `D_OPEN_EDITABLE_CANDIDATE.npvs` | Documento de la protegida en el formato abierto NPVO1 observado; candidato para comprobar edición |
| `E_OWNED_OPEN_ENCRYPTED.npvs` | Conexión de A cifrada en v5, con la política vacía/fecha de B como plantilla explícita de metadatos |

E no toma conexiones de B. El formato abierto de A no tenía metadatos de
envoltura; la plantilla se exige expresamente para no inventar un esquema de
política. C/E comprueban el cifrado: **no se anuncian como editables**. D es el
caso destinado a validar el editor abierto. En NPVO1 los metadatos exteriores,
firma y política de NPVS no existen; no deben introducirse como campos JSON
adicionales. B conserva el original completo y C preserva los metadatos exactos.

La conversión abierta solo acepta la política vacía observada. Una expiración,
restricción, nota exterior no vacía o campo de política desconocido se rechaza
en esta versión para no descartarlo silenciosamente. La reencriptación v5 sí
conserva íntegros los campos desconocidos de metadatos y documento. Contraseña,
recipient, NPVS v6 y formatos antiguos no tienen un exportador implementado
en este laboratorio y se rechazan expresamente.

Orden sugerido: A, B, C, D y E. Probar por separado para identificar cuál queda
seleccionado; si la app elimina duplicados, retirar la copia de prueba anterior
sin borrar los originales. Informar importación y acceso al editor de cada
archivo, y copiar el texto exacto de cualquier error. No usar la conexión real
como sustituto de comprobar que los campos importados coinciden.

## Reproducción privada

Python 3.12 y `scripts/requirements-npvs-lab.txt`; `androguard==4.1.4` solo
para la inspección estática. JDK con ejecución de fuentes Java para el oráculo
existente. Rutas y destinos siempre fuera del checkout; no se sobrescriben archivos.

```bash
python temporary/original-app-config-export/scripts/probe_npvs_apk.py /privado/app.apks
python temporary/original-app-config-export/scripts/create_npvs_export_matrix.py \
  --protected /privado/protegido.npvs --owned-open /privado/abierto.npvs \
  --output-dir /privado/matriz-nueva
python temporary/original-app-config-export/scripts/npvs_export_experiment.py \
  --source /privado/protegido.npvs --mode sealed --output /privado/reencriptado.npvs
python temporary/original-app-config-export/scripts/npvs_export_experiment.py \
  --source /privado/protegido.npvs --mode open --output /privado/candidato-abierto.npvs
python -m unittest discover -s temporary/original-app-config-export/scripts \
  -p 'test_npvs_export_lab.py' -v
python -m unittest tests.test_npvs_v5_embedded tests.test_npvs_protected \
  tests.test_npv_text tests.test_npvs_v5 -v
python scripts/apk_analysis/npvs_verify.py /privado/matriz-nueva/B_PROTECTED_ORIGINAL.npvs \
  /privado/matriz-nueva/C_PROTECTED_REENCRYPTED.npvs \
  /privado/matriz-nueva/E_OWNED_OPEN_ENCRYPTED.npvs
```

`--mode rewrap` entrega los mismos bytes del archivo autenticado. La CLI no
imprime configuraciones y crea destinos con permisos 0600 mediante creación
exclusiva. Un input inválido no se interpreta otra vez como otro formato.

No se corrigió un fallo reproducible del lector de producción: ambas muestras
coinciden con sus respectivos formatos. Se añade el escritor experimental y
el reconocimiento NPVO1 solo dentro del laboratorio. La antigua regresión real
de 5443 bytes no es ninguno de estos adjuntos; sus siete tests opcionales se
omiten, sin presentarlos como pasados. Las muestras actuales sí se verifican
completas por tres recorridos criptográficos.

## Aceptación manual posterior

El propietario informó que **ninguno de los cinco archivos dio error**.
Se registra importación aceptada globalmente para A/B/C/D/E, con los hashes del
paquete entregado, en `results/npvs_manual_import_report_2026-10-27.json`.
No se detallaron por separado edición por archivo, conexión real ni build
instalado; tampoco se midieron hashes en el dispositivo. La aceptación no se
extiende a otros modos NPVS, políticas o versiones. Sigue sin añadirse banner.

El propietario solicitó después una propuesta para Android/API que retire
contraseña del archivo, HWID o destinatarios tras un descifrado autorizado.
El escritor actual sigue limitado a v5 app-key sin destinatarios; no se anuncia
todavía conversión de passphrase/recipient por esta prueba. El plan y las
ampliaciones necesarias están en `ANDROID_API_COMPATIBLE_EXPORT_PLAN.md`.

Resultados sin secretos en `results/npvs_*_2026-10-27.json`. Compatibilidad
actual: **local verificada e importación de los cinco casos aceptada por el
propietario; otras variantes y pruebas funcionales no individualizadas**.
