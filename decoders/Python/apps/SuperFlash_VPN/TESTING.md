# Comprobación puntual — SuperFlash VPN 184.0.1

Fecha: **2026-10-22**. Autorización expresa para ambos catálogos externos.

| Fuente | Bytes | Versión | Registros | Campos procesados / no vacíos |
| --- | ---: | --- | ---: | ---: |
| servers.sv5c | 331166 | 2 | 234 | 2532 / 1928 |
| users.sv5c | 1233 | 4 | 1 | 6 / 6 |
| servers-download.bin | 412505 | 27 | 268 | 2894 / 2183 |
| users-download.bin | 1233 | 5 | 1 | 6 / 6 |

Ambas fuentes HTTPS oficiales responden HTTP 200. Firma Ed25519 y etiquetas
XChaCha20-Poly1305 de todos los registros verificadas; descifrado de todos los
campos AES-CBC, incluidos nombre, bandera e información de servidores.
No se presenta el JSON visible de metadatos como un catálogo descifrado.

Cada documento completo coincide con una referencia independiente:
`superflash_vpn_native_oracle.py` emula las funciones KDF/AAD originales de
`libspeigoshield.so` en 0x19234 / 0x1997c; libsodium del sistema abre los registros
y verifica la firma; JDK ejecuta AESED y Servers.decoder para los campos.
No importa el lector bajo prueba. Su SO de entrada se verifica por SHA-256.
No se ejecuta Android ni se modela una sesión remota.

El CLI stdin fuera del repo, el worker aislado real y el CLI `--all` mediante
HTTPS real coinciden con el par completo de referencia. Salida: **235989 bytes**,
`isPartial:false`; conserva las versiones independientes, todos los tipos,
metadatos, opciones xhttp y campos desconocidos.

**3 comprobaciones Python y 30 web aprobadas**:

```bash
python -m unittest tests.test_superflash_vpn -v
cd cloud/web
node --test tests/superflash-vpn-remote.test.mjs tests/server-vpn-catalog.test.mjs
```

Vectores sintéticos generados con el KDF/AAD nativo original, libsodium y JDK.
Su clave pública de pruebas solo se sustituye dentro del proceso de pruebas;
el lector/CLI/worker de producción la rechazan y no tienen opción para omitir
firmas. Los negativos firmados cubren tag alterado, índices, sobrantes, JSON
duplicado, campo AES inválido y metadatos en conflicto. También se comprueban
truncamiento/firma incorrecta, límites, ambos propósitos/fuentes, faltantes,
redirecciones, DNS privado, TLS, transporte binario íntegro y controles públicos.

Para reproducir la referencia con copias privadas fuera de Git:

```bash
python tests/golden/superflash_vpn_native_oracle.py library.so captura.sv5c salida-privada.json
python tests/golden/superflash_vpn_generate.py library.so
```

PNG original: **16109 bytes, 192×192**, SHA-256 `69a0efc8ac0e713e705c7935524e340b99f7dd5c6404cdb4162cd60b0deae214`.
Sin conversión ni reconstrucción del XML adaptativo. Herramientas ELF/JNI y
emulación ARM64 conservadas en `scripts/apk_analysis/`; dependencias ya fijadas.

SHA-256 de fuentes:

- `servers.sv5c`: `912ffd04f137c24223d57f824c802f106eb34f10efa363010f2308c358484ac0`.
- `users.sv5c`: `208cb9271a01bb7c7a8eb89848fdab708715b6041f2ffc9471293ee652509f9b`.
- `servers-download.bin`: `21a287e0a5226231e421ac6b16b114a3d1be30ca7ce782895def1680923c53cb`.
- `users-download.bin`: `0d276bc2717d650fc5c76fe5030fbe542365c310de870d0022e91f400074df0a`.

Sin suites completas por petición del usuario. Python HTTPS/CLI y worker
aislado reales; Node DNS/IP/TLS y respuesta HTTP del worker controlados.
`git diff --check` aprobado. No VPS desplegada, CI remota aprobada, sesión VPN,
perfil exportado certificado, fusión o publicación APK acreditados.
APK, SO, catálogos reales y resultados con cuentas permanecen fuera de Git.
