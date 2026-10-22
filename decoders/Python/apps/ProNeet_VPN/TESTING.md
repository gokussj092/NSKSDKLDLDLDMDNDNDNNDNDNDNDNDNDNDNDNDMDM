# Comprobación puntual — ProNeet VPN 27.11 (88)

Fecha: **2026-10-22**. Autorización explícita para las consultas externas.
Inspeccionados `ConfigUpdate`, `ConfigUtil`, `AESCrypt`, `LoadConfig`,
`SettingsConstants`, modos de `Settings` y el icono referenciado por el manifiesto.

| Fuente incluida | Bytes cifrados | Versión | Servidores | Campos procesados / no vacíos |
| --- | ---: | --- | ---: | ---: |
| `assets/config/config.json`, usuario | 38028 | 1.0.0 | 25 | 575 / 266 |
| `assets/config/config.mvgl`, token | 38253 | 1.0.0 | 23 | 529 / 306 |

SHA-256 de ambos assets cifrados:

- Usuario: `8cc07cd287ef6538dc4d164d1924b987a0b7786ea71c65a1cb87ad8dbffa7441`
- Token: `bb9ce7a7bf4cd1ce36f30bc0f03e1aae3490d234cf0c21ebd77500386845ec46`

Ambos JSON y los **572 campos no vacíos** coinciden íntegramente con el oracle
JDK `proneet_vpn_oracle.java`. CLI stdin desde fuera del repo abre cada asset;
el sobre dual atraviesa el worker aislado con documentos idénticos,
`isPartial:false`, **68794 bytes** renderizados. No se truncan listas ni campos.
Los vectores públicos son sintéticos y se regeneran con
`python tests/golden/proneet_vpn_generate.py`, sin importar el lector Python.

**Resultado remoto real:** las dos URLs exactas del APK responden HTTP 200,
**un byte `0A` cada una**. SHA-256 de cada respuesta:
`01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b`.
Las rutas GitHub Contents API de `MODO USUARIO` y `MODO TOKEN`, rama main,
confirman el mismo salto de línea. No es un fallo de autorización o de clave.
Los comandos reales `--usuario` y `--token` rechazan esas respuestas con código
1 y stdout vacío; no hay catálogo remoto descifrado ni recuento remoto válido.
La tarjeta pública permanece desactivada incluso con disponibilidad forzada.

**3 comprobaciones Python y 20 web aprobadas**:

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_proneet_vpn -v
cd cloud/web
node --test tests/server-vpn-catalog.test.mjs
```

Cubren los 23 campos, dos modos/versiones, Unicode, límites de bloque AES,
registros duplicados, valores vacíos y metadatos/tipos; worker, CLI fuera del
repo, rechazo de ciphertext inválido, símbolos fuera de índices 0–64,
truncamiento, claves JSON duplicadas, no finitos, secciones inválidas, límites,
sobre sin una fuente, respuestas remotas en blanco y redirecciones. Web
verifica icono, catálogo monotónico y rechazo del proveedor remoto no validado.

WebP original: `res/mipmap-xxxhdpi-v4/ic_launcher.webp`, 192×192, 9402 bytes,
SHA-256 `8681e5d520c746e17202241366fb50bf8027f1cdabbdc829608ff145af3db823`.
PNG Cloud: 14777 bytes, SHA-256
`3158eca3593b48108561aea234d3015f3e0e3c3c05fe4454bd86e78984aa1693`.
Píxeles RGBA idénticos; original conservado, sin redimensionar.

Según lo solicitado, sin suites completas. HTTPS externo y rechazos del CLI
reales; la validación positiva corresponde a los assets y vectores, no a las
fuentes remotas vacías. No se certifican CI remota, VPS, sesión VPN, ejecución
Android, exportador ni archivo de perfil independiente. APK, respuestas y
catálogos con cuentas descifradas quedan fuera de Git.
