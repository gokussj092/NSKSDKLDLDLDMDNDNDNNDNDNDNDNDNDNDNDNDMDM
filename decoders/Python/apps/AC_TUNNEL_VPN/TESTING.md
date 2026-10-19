# Validación — AC TUNNEL VPN 1.4

## Evidencia original

- ZIP entregado, SHA-256:
  `3a0a015a432ce72798e07ff259e48071fa0e1e88a895aae9decf573575e12eb9`.
- `base.apk`, 30524663 bytes, SHA-256:
  `4a537ae26ec1c60dfeba02e33e2f8502cd7f5a06c75887ca2bb768685e0c0b56`.
- ARM64 `libovpn3.so`, 7108808 bytes, SHA-256:
  `e896648449f786ebca76b65bc0828f59b58dec5343ff140177e1ed4f4781cbf2`.
- Icono original, SHA-256:
  `daa281539ca616d5cab7cf674b8ec6e157dd765e2b4907620006ea82567c5d45`.

Se decodificaron 1995 constantes mediante el decodificador Java original `eq.a`
para leer los consumidores sin inferir claves. Rutas comprobadas:

- `ACTUNNELVPNMain.onActivityResult`, solicitud 1999: escribe
  `actunnelvpn://` + `hi1.d(JSONObject.toString())`; solicitud de archivo `.actun`.
- `g0(Uri)` y `R(String)`: validan el prefijo, llaman al tipo 0 y luego aplican
  PIN/caducidad. Los lectores conservan esos indicadores.
- `T()` y listener `r`: descargan el catálogo fijo; `d.x()` lee el recurso
  `R.raw.f` (`res/aa/e.js`) o la actualización `a.rlb` dentro de `classes9.dex`.
- Solicitud 1996: importa `.js`/`.rj` usando el mismo tipo 0.
- `hi1.b/c/d/e`, `RenzUtils_encrypt/decrypt`, `encryptSpecial`,
  `decryptSpecial`, `encryptSensitive` y `decryptSensitive`: tipos 0/1/2.
- `n`, `x20`, `y20`: las referencias `acvpn://` identifican archivos Cloud;
  no se usaron credenciales incorporadas ni se descargaron perfiles de cuenta.

## Paridad completa local y remota

| Muestra | SHA-256 cifrado | Resultado |
| --- | --- | --- |
| Local | `ccf760424d2124e331398bd8120fe53126b9039f3cc1cf81296118efc153d7d3` | 1 servidor, 1 red, JSON completo idéntico |
| Remota HTTP 200 | `4cb6d0015d5e1d7ef858952fc833657b533c3c7481bec7fcda086e5b2b39c8c6` | 24 servidores, 1248 redes, JSON completo idéntico |

Oráculo independiente: instrucciones ARM64 originales de `xxtea_encrypt`,
`xxtea_decrypt`, `threefishSetKey` y cifrado/descifrado Threefish en Unicorn.
Se simulan asignación de memoria y copias; no se modifica el APK ni se ejecutan
/parchean controles de firma, inicialización, sesión o paquetes JNI. El paso
±2 y las selecciones de claves se contrastan con el desensamblado original.
HKDF/PBKDF2 y 12 vectores de las tres capas se verificaron también con OpenSSL
CLI, independiente del AES PyCryptodome del lector. No se presenta esto como
una ejecución completa de la aplicación Android.

Se comparan todos los campos, listas y tipos con igualdad del JSON completo;
6319 campos cifrados remotos no vacíos y 12 locales. La salida del lector mide
739081 bytes para el catálogo remoto y 1042 para el local. Ambos pasan además
por `decode_provider_catalog()` en el subproceso aislado real con
`isPartial=false`. El CLI sin argumentos se prueba con la descarga real.
Los catálogos y sus valores reales permanecen fuera de Git/CI/ZIP.

## Regresión reproducible

```bash
python -m pip install pycryptodome==3.23.0
python -m unittest tests.test_ac_tunnel_vpn -v
```

`tests/golden/ac_tunnel_vpn_vectors.json` contiene exclusivamente datos falsos,
dominios `.invalid`, contraseñas de prueba y cifrados producidos con las
primitivas nativas del APK. Cubre:

- JSON completo de perfil/catálogo, Unicode y emoji, múltiples bloques,
  todas las ubicaciones protegidas y conservación de metadatos desconocidos;
- un criptograma AES que termina en cero antes del relleno Threefish;
- referencia Cloud offline y separación estricta del perfil;
- compatibilidad de rutas RENZ anteriores y texto histórico;
- campos dañados, duplicados, profundidad, tipos incorrectos, números no
  finitos y Unicode inválido; sin resultados parciales;
- límites, URL fija, HTTP fallido, HTML, compresión, redirecciones y errores
  sin filtrar valores de entrada;
- bundle aislado con copia exacta de `renz.py`, ambos CLI y stdin;
- icono original, checksum, registros y frontera de subproceso Cloud.

Verificación nativa opcional, solo con la biblioteca original proporcionada
por el usuario, Unicorn, pyelftools y OpenSSL:

```bash
python tests/golden/ac_tunnel_vpn_oracle.py /ruta/libovpn3.so
```

El verificador no importa el lector de producción ni necesita conexión. Las
pruebas ordinarias usan vectores congelados y no necesitan el APK/ARM64.
No hay muestra independiente de exportación `.actun`: pendiente de certificación
con un archivo real. La versión nativa y el catálogo remoto sí están verificados.

## Resultado de la verificación local

19 de octubre de 2026: **633 pruebas Python**, correctas con **9 omisiones
existentes**; incluyen **13 controles AC**. Worker **11**, VPS/QA **39**, gates
Cloud **4**, Node **64**, todos correctos. `npm run build` satisfactorio. El
bundle aislado se prueba sin `PYTHONPATH` del repositorio y se comprueba la
identidad del módulo RENZ compartido. Se mantienen los avisos históricos C2
sin reescribir snapshots. No se compila ni se ensaya Android en este análisis.
