# Wolf Custom VPN: recuperación y continuidad (2026-10-31)

Solicitud actual: incorporar `core.vpn3jx.xtreme` al catálogo SP-DECODE. Continuar en `fix/http-jireh-current-method`, cuenta/conector Goku. No fusionar main, desplegar, compilar Android ni activar GitHub Actions automáticamente. Los cambios anteriores Jireh/JyFast están en `1db49db1b054a40a1347f8989693dd5da8604adf`.

## Entrada persistente confirmada

- Nombre real: **Wolf Custom VPN**, paquete `core.vpn3jx.xtreme`.
- APK analizado: **v2.8.1.2, versionCode 13**, confirmado por manifiesto binario; no deducido de la ficha web.
- XAPK original: **59349423 bytes**, SHA-256 `d82f07a06fb9b0e1e42e1b0010601c65697bd595057b6a323db5eec5ad59a58d`.
- Base APK: **30511568 bytes**, SHA-256 `7511b35542ba6ab0f75bfc01808038d53d007a90cd5567c5133e748ae7c83660`.
- Certificado firmante SHA-256: `bd6515d3f58f73aa59ae99ae1d2aff74c4e2665c3bd677fbefea77222e88fc6b`.
- Archivo duradero: `Wolf-Custom-VPN-2.8.1.2-build13.xapk`, Library **`libfile_2db70a357b208191b86e7a7f93ed05de`**. Guardado y metadatos aplicados correctamente. Contiene base y splits ARM64/en/mdpi; recuperar desde Library para no depender de una descarga futura.
- Descarga que funcionó: `https://d.apkpure.com/b/XAPK/core.vpn3jx.xtreme?version=latest`. `d.apkpure.net/b/APK/...` también devolvió el XAPK. La primera URL net/XAPK respondió 403 por una respuesta antigua; no usar esa respuesta como prueba de que el APK no existe. El espejo mostró metadatos v1.10 antiguos, por eso manda el manifiesto del archivo.

## Estado al guardar este punto

**Investigación en curso; incorporación aún no certificada.** No se ha habilitado un proveedor nuevo en este punto. El motor histórico `decoders/Python/ultra.py` ya tiene `wolfcustom`, `.wolf` y `.wolftunnel`, con fuente histórica `https://strongteam.co/api/wolf/`. Esos datos todavía no se validaron contra build 13: no activarlos por inferencia.

El APK trae `assets/configfile.json` cifrado y plantillas `custom1.json`, `custom2.json`, `v2inject.json`, etc. El launcher usa `res/mipmap-anydpi-v26/ic_launcher.xml`. Hay cadenas LSParanoid y fuentes `com/vpn/sandok`, `com/v2ray/ang`; localizar el actualizador/codec real, no confundir bibliotecas de Xray o Hysteria con cifrado de catálogo.

ARM64 viene en `config.arm64_v8a.apk`: `libgojni.so` (30686992 bytes, principalmente AndroidLibXrayLite), `libuz.so` (24745536 bytes) y otras libs. El lector Go existente sí lee libgojni; libuz devuelve `Unsupported Go pclntab layout`. Esto no demuestra protección del método activo. JADX 1.5.6 verificado está decompilando el base APK.

## Recuperar entorno tras limpieza

1. Recuperar la rama y leer este documento junto con `docs/cloud/SERVER_VPN_NEXT_CHAT_GUIDE.md`; el estado final por app tendrá prioridad sobre este punto intermedio.
2. Materializar el XAPK por el ID Library anterior, comprobar SHA-256 y extraer los cuatro APKs del ZIP. El binario no va en Git.
3. Crear entorno Python con `scripts/apk_analysis/requirements.txt`; usar `decompile.py --install` para JADX con hashes fijados y `dex_method.py` para validar instrucciones originales. No depender de una ruta `/tmp` previa.
4. Rutas locales temporales durante este punto: `investigation/wolf/`, fuentes JADX `investigation/wolf/jadx/`, checkout parcial `spdecode/`, venv `jireh-venv/`. Son prescindibles; el binario original y las herramientas versionadas permiten reconstruirlas.
5. Validar documento completo y campos con referencia independiente, lector/CLI y worker aislado; usar vectores sintéticos en Git. Identificar fuente activa desde el APK y comprobar GET real antes de habilitarla.
6. Conservar icono original. Añadir carpeta `decoders/Python/apps/Wolf_Custom_VPN/`, metadata/control/broker/bridge solo según evidencia. Mantener `.wolf` histórico y no inventar esquemas ni requisitos de contraseña.
7. Guardar código, pruebas y pendientes en commits `[skip ci]`, con lease del HEAD verificado. No guardar APKs, catálogos reales ni credenciales descifradas en Git. Aplicar pruebas puntuales; el usuario tiene poco crédito restante.
