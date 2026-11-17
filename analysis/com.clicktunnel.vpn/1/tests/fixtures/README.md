# tests/fixtures — Click Tunnel

- `bundled_catalog.js` — copia byte por byte del asset incrustado
  `res/raw/noobdev.js` del APK (2.684 B, SHA-256
  `98849cef22f185e650cf81aecda7e58367c848716952af71a74578886b7c0b81`).
  Catálogo v1.0.0 con 1 servidor y 1 tweak; todos los campos de texto
  van cifrados (XXTEA exterior + AES-CFB/CBC interior), sin valores en
  claro. Es material público del propio APK, no un perfil de usuario.

El fixture demuestra la lógica implementada con material real del APK,
NO prueba conectividad remota. La evidencia en vivo es la re-corrida
byte por byte documentada en `RESULTS.md` (el `live.json` completo NO
se copia al expediente: solo su SHA-256 y recuentos).
