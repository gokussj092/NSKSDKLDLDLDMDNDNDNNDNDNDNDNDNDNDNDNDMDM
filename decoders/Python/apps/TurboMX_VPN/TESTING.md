# Comprobación puntual — TurboMX VPN 143.1.26

Fecha: **2026-10-22**. Autorización expresa para catálogos externos.

| Fuente | Bytes | Versión | Registros | Campos procesados / no vacíos |
| --- | ---: | --- | ---: | ---: |
| servers.sv5c | 344032 | 3 | 240 | 2589 / 1999 |
| users.sv5c | 1233 | 3 | 1 | 6 / 6 |
| servers-download.bin | 413851 | 18 | 268 | 2894 / 2183 |
| users-download.bin | 1233 | 3 | 1 | 6 / 6 |

Ambos endpoints fijos de `t1x.dJLu5d6z$zlWUw` responden HTTP 200. Firma
Ed25519, todas las etiquetas XChaCha20-Poly1305 y campos AES-CBC verificados.
Los cuatro JSON completos coinciden con la referencia compartida independiente:
`superflash_vpn_native_oracle.py` selecciona el SO TurboMX por SHA-256 exacto,
ejecuta KDF en **0x19240**, AAD en **0x19988**, usa libsodium para firma/AEAD
y JDK para campos. El código AESED de ambos APK coincide exactamente y se
confirmaron la propiedad SSH_UDP, rotación Java y los 33 nombres de recursos.
La clave pública nativa está en 0x2111. No se dedujeron direcciones por tamaño.

El CLI `--stdin` fuera del repositorio, el CLI `--all` con HTTPS real y el worker
aislado devuelven el par completo de referencia: **236589 bytes**,
`isPartial:false`. El par real y worker de SuperFlash siguen coincidiendo
tras compartir la primitiva. Ambos lectores rechazan el release de la otra app.

**3 pruebas TurboMX + 3 regresiones SuperFlash y 31 web aprobadas**:

```bash
python -m unittest tests.test_turbomx_vpn tests.test_superflash_vpn -v
cd cloud/web
node --test tests/turbomx-vpn-remote.test.mjs tests/server-vpn-catalog.test.mjs
```

Vectores sintéticos TurboMX generados con KDF/AAD originales, libsodium y JDK;
el firmante de pruebas se sustituye solo dentro del proceso de pruebas y es
rechazado por producción. Se comprueban documentos completos, firma, tag
alterado con firma válida, índices, sobrantes, JSON duplicado, campo AES inválido,
metadatos en conflicto, truncamiento, límites, faltantes/fuentes intercambiadas,
transporte binario, DNS/IP públicos, TLS, redirecciones y controles de catálogo.

Reproducción con el SO original y capturas privadas fuera de Git:

```bash
python tests/golden/superflash_vpn_native_oracle.py library.so captura.sv5c salida-privada.json
python tests/golden/superflash_vpn_generate.py library.so
```

El generador reconoce cada SO por hash y escribe el archivo de vectores de su
aplicación; no sobrescribe los de SuperFlash al recibir la biblioteca TurboMX.
Herramientas ELF/JNI/ARM64 en `scripts/apk_analysis/` reutilizadas sin binarios.

PNG original exacto: **15861 bytes, 192×192**, SHA-256 `3f9f45bb05d49cb20a84d3fa86c90981a7e52287c13a3acf157d5cc1068b7945`.

SHA-256 de fuentes:

- `servers.sv5c`: `a521043098e858d476b3cf422f544d9ab91bb0b586d8069ee0971ded90a4f6fd`.
- `users.sv5c`: `c3e7f848b372d7ff46af66351e37d9af8063643a21f3083ddbe4812d97e22ddf`.
- `servers-download.bin`: `b9666ad35148f0e2da0b7c0af74e3bc85645717ec419584d2aef143372a27ee0`.
- `users-download.bin`: `c3e7f848b372d7ff46af66351e37d9af8063643a21f3083ddbe4812d97e22ddf`.

Sin suites completas por petición del usuario. Python HTTPS/CLI y worker
aislado reales; transporte Node/respuesta HTTP del worker controlados.
`git diff --check` aprobado. No se afirma despliegue VPS, CI remota aprobada,
sesión VPN, ejecución Android ni perfil exportado certificado. Sin merge, APK
o novedades automáticas. APK, SO, catálogos reales y cuentas excluidos de Git.
