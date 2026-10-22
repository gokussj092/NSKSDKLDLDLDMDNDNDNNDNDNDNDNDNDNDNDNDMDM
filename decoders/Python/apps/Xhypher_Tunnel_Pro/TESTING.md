# Validación — Xhypher Tunnel Pro 43

2026-10-22. Base del PR #96: `768b00ae618d4df75279d36a28126e34375309d4`.

## Pruebas puntuales

**8 pruebas Python aprobadas**: cuatro nuevas Xhypher y cuatro regresiones
RENZ seleccionadas. **46 comprobaciones web aprobadas**: catálogo/iconos,
transporte fijo, sesión autenticada, contrato de worker, controles y versión
persistente. No se ejecutaron suites completas del proyecto.

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest \
  tests.test_xhypher_tunnel_pro \
  tests.test_renz_family.RenzFamilyTests.test_all_16_extensions_positive_with_correct_profile \
  tests.test_renz_family.RenzFamilyTests.test_all_23_protocol_aliases \
  tests.test_renz_legacy_types -v
cd cloud/web
node --test tests/xhypher-tunnel-pro-remote.test.mjs \
  tests/server-vpn-catalog.test.mjs tests/server-vpn-version-sync.test.mjs \
  tests/c12-provider-controls.test.mjs
```

Cobertura nueva: JSON completo tipado, tres modos de campos, credenciales
invisibles, límite de bloques con ciphertext terminado en cero, límites,
entrada dañada/HTML/campo inválido, CLI fuera del repo y worker real aislado.
La ruta existente `.xhypher`, el alias de payload completo y el CLI auxiliar
mantienen la configuración completa de los fixtures JDK. Las regresiones
cubren las 16 extensiones RENZ, 23 aliases y variantes tipadas históricas.

Las pruebas Node usan transporte controlado para verificar URL, DNS/IP/TLS,
no redirecciones, denegación de destinos privados/fuentes arbitrarias,
broker autenticado, fallos remotos sin éxito ficticio y salida completa
coherente. No prueban el transporte Node real contra Internet o la VPS.

## Documentos reales

| Fuente | Bytes | Version | Servidores | Redes | Procesados / no vacíos |
| --- | ---: | --- | ---: | ---: | ---: |
| Recurso inicial `res/aa/e.rj` | 7832 | 1.0.0 | 1 | 1 | 21 / 15 |
| Descarga HTTPS oficial | 1386712 | 2.665 | 57 | 1161 | 10055 / 7363 |

Ambos documentos completos, no solo recuentos o campos de muestra, coinciden
con una implementación JDK separada. La descarga real cubre **5638 campos
tipo 0, 1653 tipo 1 y 72 tipo 2** no vacíos. Se preservan todos los registros,
campos desconocidos y tipos. La CLI con HTTPS real, stdin y worker aislado
coinciden con el JSON completo de referencia; salida de **858366 bytes**,
`isPartial:false`. No se publica ningún catálogo real ni valor descifrado.

SHA-256 del catálogo remoto:
`d435a57bdd74a72f84337b81a35cb2f9d4f95b37198d2afa17c6dd1758524d32`.
SHA-256 del recurso inicial:
`97b628a80785d69ce138204bbc2ec2815dd64b01f917305410546defde603850`.

## Referencias independientes y nativas

- `xhypher_tunnel_pro_oracle.java`: JCA AES-CBC/HMAC/PBKDF2 y transcripciones
  separadas de XXTEA/Threefish/codificación invisible. Semilla, IV y salt se
  confirmaron byte a byte en el SO actual antes de reutilizar RENZ.
- `xhypher_tunnel_pro_generate.py`: fixtures públicos únicamente sintéticos.
  Busca un ciphertext terminado en cero para comprobar el caso de alineación;
  no genera los valores esperados usando el lector bajo prueba.
- `xhypher_native_oracle.py`: hash exacto de `libovpn3.so`, Unicorn con límites,
  sin Android/JNI/red. **10 casos originales ARM64 aprobados**: cuatro pares de
  portador invisible/XXTEA, dos XXTEA de tipo 0 y cuatro streams Threefish,
  incluidos los tres campos reales afectados por el recorte de ceros.
  Solo malloc/calloc/free/strncmp/memcpy/memset se modelan; la criptografía
  indicada se ejecuta. No se afirma ejecución completa de JNI, OpenSSL KDF,
  Android ni del código de comprobación del APK.

El recorte de relleno se redondea a bloques CBC completos para conservar ceros
legítimos. El JDK y los bloques nativos verifican la recuperación; no se afirma
que la función compuesta original, con su recorte byte a byte, entregue esos
tres campos correctamente. CBC/XXTEA carecen de autenticación criptográfica.

## Límites

No se aportó perfil exportado real independiente, no se certifica writer ni
roundtrip Android. No se usa el acceso de enlaces cortos, ninguna credencial
incrustada de servicios ni un DEX de comprobación como si fuera catálogo.
Sin pruebas de sesión VPN, CI remoto exitoso, merge, despliegue VPS, APK o
novedades automáticas. La publicación previa C11 del PR se conserva intacta.
