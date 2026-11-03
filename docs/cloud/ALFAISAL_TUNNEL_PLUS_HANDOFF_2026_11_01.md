# ALFAISAL Tunnel+: estado y recuperación

Fecha2026-11-01, Goku, repo
`gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM`.
Rama `fix/http-jireh-current-method`, base **fd8b78c6** (IZPH).
Main sigue **5a1c93a4**; la rama todavía no está fusionada.
Revisión fuente **59**, ahora **55 fichas**, lote sin desplegar por instrucción
del propietario. Commit `[skip ci]`; sin merge, Android, Actions ni despliegue.
90NET sigue pospuesto. VIP e IZPH conservan sus métodos ya validados.

## Resultado

**ALFAISAL Tunnel+**, `app.ovpninject5.vpn`, **Version -39WH-wake /39**,
coincide con la ficha vigente de Google Play y el APK adquirido.
APK85117813bytes, SHA256
`deb89699b10ddd2c425a8f094cbdadc92059d4d93aac3d6c790b036ff662f0ea`.
Firma SHA1 `26f53fb5938dd7220980aa578bb5d882910a6bf0`, SHA256
`323e6af4a9c1493a56e62f14f9fe673fcf1df21aa6bc14ed09081b49c0462235`.

GET metadata `https://panel.alfaisalvpn.com/api/app_settings.php` anuncia
`json_requires_integrity=false`. POST firmado fijo
`https://panel.alfaisalvpn.com/api/protected_json.php`: **HTTP200,4.0.20,
4 servidores /51 Networks /103 SSLNetworks**,141420bytes, SHA256
`b6300b5218fadbee8b57001fe3612274f7328511a21c4e7903e7bf504c3c8016`.
La API requería además una instalación registrada. Se siguió una vez el
registro normal con una identidad de prueba propia, sin datos de terceros.
Se reutiliza esa instancia, nunca se registra otra por descarga.

HMAC-SHA256 sobre `timestamp.nonce.body` con clave textual UTF8, nonce16bytes,
X-API-KEY y JSON compacto exacto. Los dos secretos de API proceden del mismo
APK. Se conservan privados junto al UUID registrado. Si la política pasa a
requerir Play Integrity, la integración falla de forma explícita; no genera
atestación ficticia ni continúa sin autorización.

Bootstrap `res/0k.js`:1196bytes, SHA256
`cc3243bf5af67fdddede02a092f0adc6e3d6cecd9d7bf80813d6dadc93597d72`,
0.0.0,1 servidor /0 Networks /1 SSLNetwork. No sustituye al remoto.

## Código y validación

Carpeta `decoders/Python/apps/ALFAISAL_Tunnel_Plus`. CBC256/IVcero/PKCS7,
clave SHA256 de la contraseña de formato `gb.o`. Campos confirmados y
procedencia en README/manifest. Mantiene las tres listas enteras, tipos,
desconocidos y placeholders. `gb.m$a.b` devuelve el valor original ante
GeneralSecurityException de CBC; DEX confirmó el catch. Tres Squid antiguos
siguen ese camino en el catálogo real y se conservan, sin eliminar registros.

JADX1.5.6:33 errores generales. LSParanoid md.a/f30808a, helpersmd.b/md.c:
2329 literales /15 fuentes /2517 cadenas. No se necesita un oráculo nativo:
la apertura del catálogo y HMAC son Java/JCA. Se ignoran las librerías nativas
de transporte ajenas a ese método.

**33 Python /163 Node aprobadas,0 skips**. Documentos completos incluidos y
remotos iguales a JCA, codec, CLI stdin y worker aislado. CLI `--download`
real repite satisfactoriamente metadata+POST y devuelve el mismo documento.
Respuesta real del worker validada por C3 con HTTP interno simulado:
200,4/51/103,rawText89469bytes, igualdad completa.
El egress real de Node no está comprobado: sus transportes usan mocks.
Sin prueba de Android, conexión VPN, exportador ni producción VPS.

Broker `alfaisal-tunnel-plus`, helper de firma, allowlist worker offline,
contrato C3 para tres listas, ficha, switch persistente e icono original.
No redirecciones ni reintentos con el mismo nonce; DNS público y TLS.
Secretos solo web; no se envían al worker ni al catálogo público. Fuente59,
55 fichas,240 C0 /254 C8 /28 overrides sin nuevas rutas de archivo.
No se registra `.js` como extensión por el nombre del recurso incluido.

PNG original `res/tt.png`,192×192,24520bytes, SHA256
`17c87ccc847a7babf655170044967e9120609793381800c664b73a17ad1ebaff`;
copias exactas en la carpeta de la app y `cloud/web/public/server-vpn-icons/`.

## Originales privados duraderos y provisión

Estos IDs permiten recuperar el trabajo después de una limpieza local:

- APK **ALFAISAL-Tunnel-Plus-39WH-wake-build39.apk**:
  `libfile_49b49b439dd4819185151355ff12efef`,hash y tamaño arriba.
- Catálogo cifrado **remote.enc**:
  `libfile_c496ce0d4a3881919945f0e0de0f9f3b`,hash y tamaño arriba.
- Configuración privada **ALFAISAL-backend-secrets.env**:
  `libfile_4887525611e08191b1f0d392f3c96144`.
  Contiene los valores ya usados con éxito de
  `SPDECODE_ALFAISAL_API_KEY`, `SPDECODE_ALFAISAL_SIGNING_KEY` y
  `SPDECODE_ALFAISAL_DEVICE_UUID`. No copiar su contenido a Git, respuestas,
  capturas, logs ni argumentos. No hay JSON descifrado duradero publicado.

Para un despliegue posterior autorizado, recuperar ese archivo privado e
incorporar sus tres asignaciones a `/etc/spdecode/cloud.env` con permisos600,
sin sobrescribir los demás valores. Compose ya propaga los tres solo a web.
Comprobar que los tres están presentes sin imprimirlos, recrear web según el
procedimiento de despliegue y probar una descarga autenticada por la aplicación.
Faltando alguno, el proveedor no se habilita. Esta provisión y prueba del VPS
quedan pendientes de ese despliegue; no se han ejecutado en esta entrega.
No usar una variable vacía ni un valor sintético en producción.

Para reanalizar: recuperar APK, verificar SHA, extraer res/0k.js yres/tt.png;
JADX y `paranoid_strings.py` con
`--chunk-field f30808a --method a --call-class md.a --inventory`.
`g3.y0.a/c` concatenan cuatro fragmentos de API key y HMAC key respectivamente;
reconstruir únicamente en memoria si hace falta, no imprimir inventario/valores.
El host está confirmado en OpenVPNClient.B5/D5; g3.f1.i/g3.x0 describen registro.
La instancia privada guardada evita recrearla tras una limpieza.

```sh
python scripts/apk_analysis/alfaisal_verify.py incluido.enc remoto.enc --runtime
```

El verificador imprime solo métricas/hashes y compara todos los campos con
`tests/golden/alfaisal_oracle.java`. `alfaisal_vectors.json` usa exclusivamente
datos ficticios y permite regenerar cifrado/HMAC independientemente.
Pruebas y comandos completos en el TESTING de la app.
