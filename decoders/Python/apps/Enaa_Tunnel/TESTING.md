# Validación Enaa Tunnel — 2026-11-01

Original XAPK Enna-1.07/build7,53323023bytes, SHA256
`105f5447988349d93c7214e430c13d8a725cbeae6aaf6e74bf1e5d56a6571b5f`.
Paquete, certificado y versión comprobados; ficha viva de Play anuncia la misma
versión. JADX1.5.6 fijado produjo58 errores generales. Rutas críticas nativas
recuperadas de pclntab Go, sin afirmar ejecución de JNI/Android.

- CU0x1a4e3e0: GET, URL nativa0x3d0176/51bytes y User-Agent Enaa Tunnel.
- DO0x1a4b660 /EO0x1a4b1f0; Encrypt0x1a4a9a0 /decrypt0x1a4ad00.
- Contraseña de formato0x39a223/18bytes; Argon2id3/8192/1/32, salt AAD,
  nonce12, tag16 y letra extra confirmados por instrucciones nativas.
- Exportador Java NetworkAdapter.u e importador ConfigFileParser confirmados.

| Muestra | Versión | Servidores | Redes | Bytes | Campos protegidos no vacíos |
| --- | --- | ---: | ---: | ---: | ---: |
| assets/configfile.json | 3.20 | 28 | 465 | 709920 | 3303 |
| GET real | 4.26 | 45 | 515 | 810149 | 3555 |

Incluido SHA256 `d8c8887fac8d53c68b1a143031cade84a6887525c0a79e6b5e144576bc013edb`.
Remoto SHA256 `981ce266f94f10eaed2489401d71ce4ce9415d86bc48a6076e1f0284c4bd37b2`.
Ambos documentos completos iguales al KDF independiente **libsodium** y
AES-GCM **JDK/JCA**; no se compara solo un roundtrip de Python. El worker
procesa el catálogo remoto dentro de su presupuesto existente de120s; la CLI
repitió el GET real. Informe y métricas en manifest/handoff.

```sh
python scripts/apk_analysis/enaa_verify.py catalogo.enc --expected privado.json
python -m unittest tests.test_enaa_tunnel tests.test_cloud_c8_vpn_registry
python scripts/cloud_formats_catalog.py
```

**9 Python aprobadas**,8 Enaa y1 registro C8; **160 Node aprobadas**,0 skips.
Vectores independientes EO/DO, exportación con letra y texto JSON, Argon2id,
Unicode, campos desconocidos/URI conservados, tag externo/interno corrupto,
claves JSON duplicadas, tamaño, schemas, CLI fuera del checkout, worker de
catálogo y archivo, errores saneados y ninguna redirección.
Seis pruebas Node Enaa de DNS, redirects, icono/ficha/formatos, switch persistente,
gateway con sesión/cuota y rechazo de resultado parcial/inconsistente.
Regresiones de catálogo/proveedores/controles y fichas afectadas incluidas.

Transporte Node al proveedor y HTTP interno: **simulados**; GET real por Python.
No se afirma egress Node real, Android físico, conexión VPN ni export real .enaa.
Los únicos fixtures versionados son sintéticos. APK/SO, catálogo real y contenido
descifrado quedan fuera de Git. No se lanzan Actions ni se despliega/compila APK.
