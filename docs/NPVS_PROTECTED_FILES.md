# NPV Tunnel 124.0.37 — contraseña y destinatarios

Actualización del Python en PR #96, 2026-10-22 (hora del cliente).
Se parte de [la investigación existente](NPVS_V5_INVESTIGATION_HANDOFF.md);
no se reemplaza el evaluador white-box ni se repite su extracción.

## Resultado por archivo aportado

| Archivo | Versión / método | Resultado |
|---|---|---|
| Rjo sniff password.npvs | NPVS v5 / passphrase 1 | Completo: firma, DEK, metadatos, contexto, HMAC y 16 registros válidos; nueve campos `npvs1:` abiertos |
| Rjo public-key.npvs | NPVS v6 / recipient 0, un destinatario | Firma válida y clave pública coincidente; falta clave privada |
| Rjo normal.npvs | Exactamente los mismos bytes que public-key | Mismo resultado; no es un tercer caso normal independiente |

El problema reproducido es de **alcance del lector**: solo implementaba v5
app-key 2. Rechazaba modo 1 y versión 6 antes de descifrar. La modificación
anterior que abre campos explícitos `npvs1:` conserva sus pruebas y no es la
causa de esos rechazos. No se atribuye un fallo a la documentación original.

## Compatibilidad e integración

- Motor canónico `decoders/Python/npvs.py`, ruta `.npvs` y salida
  `metadata` / `document.configs` conservadas. No se modifica `NPVTUNNEL.py`,
  otros formatos ni tablas white-box. C0 sigue 240 y C8 efectivo 248.
- Implementado: v5 compacto 1, app-key 2/keyId 2 y passphrase 1. Nuevos kwargs
  opcionales `password` y `public_key`, sin romper llamadas `run(data)` previas.
- Reconocido y diagnosticado: recipient 0 de v5/v6; v6 añade 16 bytes después
  de los registros. **No se certifica descifrado v6 ni recipient**. Otros modos
  v6 permanecen no implementados; nunca se tratan como v5 silenciosamente.
- Se verifica framing y ECDSA antes de pedir contraseña o informar de claves.
  No hay fallback criptográfico tras fallar firma/tag. Se conserva EOF exacto.
- Worker aislado `npvs_bridge.py`, gateway `credentials.password` / `publicKey`.
  Solo stdin; sin credenciales en argv/env/logs. Límite de contraseña 4096
  bytes UTF-8 y publicKey 128 bytes; stdin JSON acotado para escapes.
- Errores seguros: `PASSWORD_REQUIRED`, `AUTH_FAILED`, `PRIVATE_KEY_REQUIRED`,
  `RECIPIENT_MISMATCH`, `INVALID_CREDENTIALS` y variante no implementada.
  Un fichero corrupto no genera un resultado parcialmente abierto.
- El diagnóstico de clave privada requerida se excluye de incidentes automáticos
  y de errores de ejecución; no significa que el motor se haya caído.
- El cliente que use contraseña NPVS debe enviar `credentials.password`.
  Este encargo actualiza Python/backend; no añade diálogos Android ni publica APK.
  La disponibilidad del servidor requiere desplegar el código del PR.

## Descriptor de contraseña comprobado

Cabecera compacta previa: versión 1, configId16, creador P-256 comprimido33,
modo u8 y número de recipients u16 BE; cada recipient ocupa 125 bytes.
Tras los recipients, modo 1 contiene:

`iterations:u32be | salt16 | wrappedDEK60 | metadataLength:u32be | metadata+tag`.

La muestra utiliza **600000 iteraciones**. El parser Go comprobado admite
600000–10000000. `KDK=PBKDF2-HMAC-SHA256(UTF8(password),salt,iterations,32)`;
DEK: nonce12 + ciphertext32 + tag16, ChaCha20-Poly1305 y AAD=salt.
Desde ahí se reutilizan las fórmulas v5 ya documentadas: HKDF metadata,
cabecera fuente canonicalizada, contexto, inventario HMAC y campos NPF.
Los nueve marcadores explícitos se abren después de autenticar el documento,
sin adivinar que otras contraseñas/cadenas son Base64.

## Por qué la public key aportada no basta

El dato proporcionado decodifica como un punto P-256 comprimido de **33 bytes**;
es una clave pública válida y `SHA256(publicKey)` coincide con el fingerprint
del único destinatario. No es una contraseña ni una clave privada mal rotulada.
Ambos archivos v6 tienen firma P-256 válida y registros de destinatario de
125 bytes: fingerprint32 + efímera33 + nonce12 + DEK cifrada32 + tag16.

La ruta Java `ah.j` llama a `ah.h.b(ECPublicKey)` para ECDH. `ah.g` utiliza la
privada de `AndroidKeyStore` bajo `npvtunnel.recipient.v1`; la alternativa
`ah.i` abre PKCS#8 desde `npvtunnel_recipient_v1.dat`, cifrado AES-GCM con otra
clave de `AndroidKeyStore` (`npvtunnel.recipient.aes.v1`). `ah.b` elige la
implementación según la instalación. El APK por sí solo no contiene esa privada
de usuario. No se ha accedido al dispositivo ni se presume su implementación
concreta a partir de estos adjuntos.

El núcleo Go `unwrapSealedDEK` usa ECDH para abrir la DEK y la ruta v6 aplica
además `maskCompactRecipientKey`/`compactRecipientPad`. Se inspeccionaron ambas;
la máscara de aplicación no elimina la necesidad previa de ECDH. No se intentan
contraseñas inventadas ni se presenta una public key como material secreto.
Pendiente una exportación con otro método o material privado legítimo del
destinatario; no se implementa un importador de privadas sin una muestra real.
También falta una exportación normal distinta para comprobar el caso solicitado.

## Fuentes y hashes

| Fuente | Bytes | SHA-256 |
|---|---:|---|
| APKS aportado | 30304019 | `1877c261369b0fca5644c2aa934bdf1b46295115b54890ce0b5b99ba5d7ef241` |
| base.apk | 22344543 | `1999c5748b1ab1cc9a314573052665c96619cdd3bef570704e778ad5b5901a74` |
| libgojni.so ARM64 | 38920432 | `ea5c68f088256b648b91c0ca009ad7f6d144e5d107608f622a5f564c9bc8891b` |
| libnpvtunnel.so ARM64 | 58296 | `6ba05d3ac27f28b1b058b1162c0c0de0009fff47fc876b7e924f3288b1fd7c89` |
| rt.dat | 749617 | `0c56b43e7a60e312e80ff163088f32ab25c4bdbbcd677f046c78d9f61b0cd9fd` |
| archivo passphrase | 1352 | `a3eb8004c523d90fea23e61e619b1c13c881b97b2f006b1755f2eda2f8797a49` |
| normal y public-key | 1413 cada uno | `c7dc276dcfa73a66e33cd1c96f4f4b17cdf0e3f3d726134efb950c4dcd06e41c` |

Bibliotecas y recurso coinciden con la investigación original; se mantienen sus
tablas. JADX 1.5.6 finalizó con 79 errores generales; las rutas `ah.m/j/g/i/b`
citadas se contrastaron con Go/ASM y no se usa ese estado parcial como prueba
de descifrado. No se ejecutó la app ni un SO completo.

## Herramientas conservadas y comprobaciones

`scripts/apk_analysis/go_inspect.py` lee pclntab f1/64 y resuelve textStart desde
`runtime.moduledata` relocado: aquí **0x11ff610**, no `.text=0x11ff5c0`.
Evita repetir el desplazamiento de 0x50 señalado en la investigación original.
Permite filtrar nombres y desensamblar un símbolo exacto, sin ejecutar Go.

| Función comprobada | VA |
|---|---|
| parseCompactHeader | `0x1f1f090` |
| compactRecipientPad / maskCompactRecipientKey | `0x1f1fe80` / `0x1f20250` |
| unwrapSealedDEK | `0x1f23f10` |
| openSourcePassphrase | `0x1f4b7f0` |
| openSourceWrappedKey | `0x1f4c040` |

`npvs_verify.py` compara el documento íntegro con el oracle JDK independiente
`tests/golden/npvs_protected_oracle.java`: framing, ECDSA P1363, PBKDF2,
ChaCha20-Poly1305, HKDF e inventario/16 registros reales. Un reconstructor Python
de referencia separado comprueba contexto, todos los valores y las capas
`npvs1:`. JDK no usa el parser/cripto de producción; para app-key recibe el
bloque white-box previamente validado con vectores ARM64.

**16 pruebas Python y 15 Node aprobadas**, con regresiones app-key y campos
embebidos. CLI real fuera del repo, worker aislado completo y worker HTTP local
autenticado verificados. Gateway Node con transporte controlado; sin suites
completas, despliegue VPS, Android instrumentado, conexión VPN ni catálogo nuevo.
Comandos en `scripts/apk_analysis/RESTORE.md`. Binarios, archivos reales,
credenciales y resultados privados quedan fuera de Git.
