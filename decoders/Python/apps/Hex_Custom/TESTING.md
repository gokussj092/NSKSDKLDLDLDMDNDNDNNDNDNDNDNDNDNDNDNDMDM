# Validación de herramientas, no de descifrado de archivos

2026-10-23:

- **6 pruebas** de recuperación aprobadas: preservación íntegra de payloads
  opacos y firma, framing, versiones, UTF-8/JSON, manifiesto duplicado,
  rangos duplicados/solapados/incompletos, biblioteca no admitida y salida 0600
  que no sobrescribe archivos.
- **10 regresiones** aprobadas: 9 del lector CREEB VPN y 1 del registro C8.
  Total de esta ejecución: **16 pruebas Python**. Sin suite global.
- Biblioteca real fijada por SHA-256: tabla de **10 métodos**, clase exacta,
  tres paquetes con cobertura íntegra y hashes reproducibles.
- **546488 bytes del pool iguales** entre transformación estática y bucle XOR
  ARM64 aislado del SO original. Se ejecuta solo ese bucle, sin JNI/VM/red.
- Corrección de PLT de 24 bytes: cuatro wrappers nativos originales de AboWaged
  siguen coincidiendo con sus argumentos Java y claves documentadas. Es una
  regresión de la herramienta ELF, no una prueba de Hex Custom descifrado.

```bash
python -m unittest tests.test_hex_custom_recovery tests.test_creeb_vpn tests.test_cloud_c8_vpn_registry
python scripts/apk_analysis/hex_custom_recover.py /ruta/libkovsec.so /ruta/kov-sec.dat /ruta/privada-nueva --verify-xor
python scripts/apk_analysis/abowaged_native_oracle.py /ruta/abowaged/libwg-pro.so
```

Dependencias de análisis en `scripts/apk_analysis/requirements.txt`: pyelftools,
Capstone y, para --verify-xor, Unicorn. No se necesitan en runtime de SP-DECODE
porque **no se incorporó un motor Hex Custom funcional**.

No se recibió archivo exportado; no hay vector real o sintético de archivo,
paridad de descifrado, KDF confirmado o prueba de contraseña. Ninguna prueba de
recuperación sustituye esa validación. Métodos de archivo, extensión y requisito
de contraseña permanecen pendientes. No se habilitó tarjeta, formato o decoder.
