# Validación de 7NET VPN 5.6

Comprobación del 2026-10-22 sobre el APK aportado por el usuario y su catálogo
público fijo. Los fixtures publicados contienen exclusivamente datos sintéticos
`example.test` y usuarios de prueba. No hay llamadas remotas en los tests CI.

## Evidencia real

| Fuente | Version | Servidores | Redes | Campos / no vacíos | Paridad |
| --- | --- | ---: | ---: | ---: | --- |
| `res/ae/g.js` | 1.0 | 92 | 634 | 6347 / 4982 | JSON completo igual a JDK |
| URL del updater, HTTP 200 | 40.19 | 76 | 619 | 6025 / 4750 | JSON completo igual a JDK |

El JDK usa JCA/HMAC/PBKDF2 y transcripciones independientes de XXTEA y Threefish;
no importa los algoritmos del lector Python. El oracle nativo verifica SHA-256
del SO y ejecuta exclusivamente primitivas offline con límites de memoria e
instrucciones: **9 casos por fuente / 18 ejecuciones aprobadas**, incluyendo
los flujos Threefish cuyo ciphertext legítimo termina en cero.

Hay seis campos afectados por el recorte de ceros en cada muestra; los valores
completos se recuperan conservando el bloque AES. Todos se comparan con JDK;
no se afirma que CBC/XXTEA/Threefish autentiquen los mensajes.

La descarga CLI HTTPS real, stdin desde `/tmp` y el worker Cloud aislado son
iguales al documento completo: Version 40.19, **502968 bytes**, sin parcialidad.
Las pruebas web usan transporte controlado; no se afirma un despliegue en VPS
ni una prueba de sesión Android en producción.

## Comprobaciones puntuales aprobadas

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest \
  tests.test_sevennet_vpn tests.test_xhypher_tunnel_pro \
  tests.test_renz_family.RenzFamilyTests.test_all_16_extensions_positive_with_correct_profile \
  tests.test_renz_family.RenzFamilyTests.test_all_23_protocol_aliases \
  tests.test_renz_legacy_types -v

cd cloud/web
node --test tests/sevennet-vpn-remote.test.mjs \
  tests/xhypher-tunnel-pro-remote.test.mjs tests/server-vpn-catalog.test.mjs \
  tests/server-vpn-version-sync.test.mjs tests/c12-provider-controls.test.mjs
```

**12 Python y 54 web aprobadas**, sin ejecutar suites completas del proyecto.
Cubren documento íntegro, CLI, worker real, archivos/aliases históricos,
credenciales, límite CBC, datos corruptos, límite de entrada, URL fija,
redirecciones, DNS privado, contrato del worker, icono, switches y versión.
No se aportó un perfil real independiente del exportador: su validación es
sintética y la certificación del exportador sigue pendiente.

## Reproducción en otro entorno

Desde la raíz del repositorio, con Python y JDK 17+:

```bash
python tests/golden/sevennet_vpn_generate.py
python scripts/apk_analysis/sevennet_verify.py copia-catalogo.txt --runtime
python scripts/apk_analysis/sevennet_verify.py copia-catalogo.txt \
  --native ruta-al-SO-original/libovpn3.so --runtime
```

El verificador imprime solo hashes/recuentos y resultados de paridad. La
opción `--native` requiere exactamente el SO del build analizado; no ejecuta
JNI, Android, código descargado ni servicios externos. Los catálogos y SO
reales deben permanecer en una carpeta privada excluida de Git.

Los scripts, versiones, checksums de JADX y comandos de arranque permanecen en
`scripts/apk_analysis/`; `RESTORE.md` explica la recuperación desde el PR.
