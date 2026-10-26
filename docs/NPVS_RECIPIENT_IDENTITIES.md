# NPV Tunnel 124.0.37: contexto JSON e identidades de destinatario

2026-10-25, hora del cliente. Continuación en PR #99; mantiene lectores
históricos y todo el trabajo de catálogo anterior. No publica APK ni despliega
VPS. La implementación nueva necesita ambos componentes actualizados.

## Error reproducido y resuelto

Las tres muestras `RIFI IAM ⋆ 6 V2 ☂ ❸/❹/❺.npvs` son **NPVS v5, app-key 2,
cero destinatarios**. No necesitan la privada del usuario. El lector anterior
verificaba ECDSA y abría DEK/metadatos, pero fallaba en
`Invalid field container or metadata binding`.

`policy.displayMessage` contiene HTML. `_canonical` escapaba `<`, `>` y `&`
con los defaults históricos de Go JSON v1. El escritor del APK
`writeCanonicalSealedString` solo escapa la gramática JSON: comillas, barra
inversa y controles; conserva HTML y U+2028/U+2029. Se corrigieron Python,
el verificador independiente, generador sintético y `NpvsJson.kt` offline.
No se omite ni relaja el vínculo del contexto, la firma, tags o inventario.

| SHA-256 del archivo | Resultado |
|---|---|
| f661576e3b83eedbdf57f1e210d24b2f26edc93968594271fa5caf3d181df9f7 | Completo, un config |
| 0d7d02426cf8f8203c04728703be12e0cdf072be1361d310d02b0e7f22f431b3 | Completo, un config |
| 1502669ce25e8f20272752ef66ae7dab68f7f17e7655d0e0165682a39b502c8f | Completo, un config |

JCA independiente: tres documentos y **72 registros** autenticados; JSON
completo y campos `npvs1:` iguales al worker aislado. Los archivos originales,
metadatos privados y resultados descifrados permanecen fuera de Git/CI.

## Método de destinatarios

- Identidad ECDH **secp256r1/P-256**. Pública SEC1 comprimida33; fingerprint
  SHA-256 de esos33 bytes; privada PKCS#8 DER. Intercambio Base64URL sin padding.
- Registro125: fingerprint32, efímera33, nonce12, ciphertext32 y tag16.
- ECDH devuelve X de32 bytes BE. HKDF-SHA256: IKM=sharedX,
  salt=fingerprint32, info=`NPVS-v1-wrap || configId16`, salida32.
- AES-256-GCM abre la DEK con nonce del registro y AAD=fingerprint32.
- En v6, después de los registros hay maskSalt16. KDK=
  SHA256(`npvtunnel/appkey/v2 ` || whitebox(maskSalt) || configId).
  Pad=HKDF-SHA256(KDK, salt=maskSalt,
  info=`NPVS-v6/recipient-binding || configId`,32). XOR abre la DEK real.
- Metadata sigue usando HKDF info `NPVS-v5/metadata`, también en v6.
  El **contexto fuente sí depende de la versión**:
  `SHA256(NPVS-v{version}/source-fields-v1/ || canonical(sourceHeader) || nonce)`;
  `sourceHeader.v` es5 o6. No se hereda sin comprobar el prefijo v5.
- Se autentican metadatos ChaCha20-Poly1305, contexto, inventario HMAC y todos
  los registros/layout NPF. No hay fallback después de un error criptográfico.

Evidencia APK: paquete `com.napsternetlabs.napsternetv`, build577, base SHA-256
`1999c5748b1ab1cc9a314573052665c96619cdd3bef570704e778ad5b5901a74`;
libgojni SHA-256 `ea5c68f088256b648b91c0ca009ad7f6d144e5d107608f622a5f564c9bc8891b`.
`GoImage` resuelve textStart por moduledata. Símbolos AArch64 de esta biblioteca:

| Símbolo libnpvtunnel | Dirección |
|---|---|
| writeCanonicalSealedString | 0x1f332e0 |
| unwrapSealedDEK | 0x1f23f10 |
| compactRecipientPad | 0x1f1fe80 |
| maskCompactRecipientKey | 0x1f20250 |
| compactMetadataKey | 0x1f203e0 |
| sourceDocumentContext | 0x1f4e050 |
| openSourceRecipientWithValidation | 0x1f4b4b0 |

El orden sal/AAD=fingerprint, info=label+configId se confirma en `ah.m.e`,
`ah.j.c` y `unwrapSealedDEK`: la sal pasada al HKDF es el argumento fingerprint
de32 bytes y el sufijo copiado al info mide16 bytes. No intercambiar esos campos.

Java `ah.j` usa `ah.g` (ECDH AndroidKeyStore, alias
`npvtunnel.recipient.v1`) o `ah.i` (PKCS#8 cifrado en
`npvtunnel_recipient_v1.dat`, AES-GCM alias `npvtunnel.recipient.aes.v1`).
La elección depende de la instalación. El APK no contiene una privada universal.
Python reproduce las primitivas y serialización, **no el Keystore de hardware**.
No se encontraron fuentes Swift en este repositorio; el contraste se realizó
con los lectores Python/Kotlin actuales y el código Java/Go del APK adjunto.

## API y Android Cloud

`POST /api/v1/npvs/identity`, sesión existente y `{"consent":true}`: worker
interno genera P-256 aleatorio, devuelve identidad una vez; gateway comprueba
privada/pública/fingerprint y responde201 con no-store. Mismos controles de
sesión, mantenimiento y concurrencia; no guarda las claves en Redis, base de
datos, métricas, incidentes o logs. La privada necesariamente pasa por el
servidor porque el usuario solicitó generación por API.

JSON `spdecode.npvs.recipient.v1`, `kind=keypair`, `source=generated|captured`,
`curve=P-256`, `fingerprint`, `publicKey`, `privateKey`. Una captura de hardware
usa `kind=agreement`, `source=captured`, `fingerprint`, `fileSha256`, `peer` y
`sharedSecret` en lugar del par. Este acuerdo se acepta únicamente para el
archivo exacto y efímera coincidente; se vuelve a autenticar todo el documento.
No es un sustituto reutilizable de la privada.

Android: nueva sección en Ajustes de las fuentes **generadas de Cloud**, sin
modificar los nueve archivos UI congelados C0. Vault independiente con AES-GCM
AndroidKeyStore, `noBackupFilesDir`, escritura atómica, función apagada por
defecto. Generar, importar JSON acotado/estricto, borrar, ver/copiar pública y
privada con diálogo seguro. No se reutiliza ni cambia el vault S4 histórico.
Un selector no exportado recibe un ticket opaco, no claves en Intent; pide
elegir identidad coincidente y confirma envío de material por HTTPS. Comprueba
de nuevo opt-in/archivo antes del envío; cancelar no envía la clave. Archivos
app-key y passphrase mantienen su flujo. El protocolo de archivo añade
`credentials.recipientKey` (JSON string, máximo16384 bytes) y lo entrega al
proceso aislado por stdin. No hay credenciales en argumentos o entorno.

El cliente negocia `X-SPDecode-NPV-Identities: 1` para recibir el nuevo
campo de credenciales. Los APK anteriores reciben los nombres históricos para
no invalidar su caché; un cliente actualizado refresca la instantánea anterior.

Catálogo de metadatos49, sin nuevas fichas Server VPN: C0 240, C8 254,47 fichas.
Se conservan estados previos de interruptores. Otros métodos v6 y recipientes
v1 históricos no se anuncian como implementados por esta continuación.

## Validación y límites prácticos

`tests/test_npvs_identity.py` genera pares nuevos, crea archivos sintéticos
v5/v6, compara documentos completos con JCA ECDH/AES/ChaCha/HMAC y worker,
verifica claves mezcladas, destinatario erróneo, firmas/tags alterados,
captura ligada a archivo, API interna, colector y bundle autónomo. El oracle
Java recibe secretos solo por stdin y nunca imprime la privada.

`tests/npv_recipient_capture.test.mjs` comprueba argumentos/resultados originales,
errores, limpieza de arrays, versiones y archivo correcto con mocks. API pública
comprueba sesión, consentimiento, claves frescas/coherentes y no persistencia.
Las tres muestras reales son app-key; **no constituyen una prueba real de
exportación de destinatarios**. Faltan un intercambio con el exportador oficial
y pruebas físicas Android/root/Frida. No afirmar identidad del100 % con un
Keystore ni que root permita exportar siempre la privada.

Uso: [guía Termux](NPV_RECIPIENT_TERMUX.md). Recuperación reproducible:

```sh
python -m unittest tests.test_npvs_identity tests.test_npvs_protected tests.test_npvs_v5.PrimitiveTests
node --test tests/npv_recipient_capture.test.mjs
python scripts/apk_analysis/npvs_verify.py /privado/uno.npvs /privado/dos.npvs /privado/tres.npvs --worker
python scripts/apk_analysis/npv_termux_bundle.py /privado/npv_termux_bundle.zip
```
