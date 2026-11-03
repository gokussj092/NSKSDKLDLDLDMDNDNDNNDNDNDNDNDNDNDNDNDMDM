# Validación ZiG Tunnel Play1.0 — 2026-11-01

Original analizado XAPK **1.0/build1, armeabi-v7a**,50260248bytes, SHA256
`b0ad45525bc33d3ebc1ae85ddd7b62dcab10ae68a457eaffd71a313958bffad4`.
Base APK SHA256 `ba0a374ad191ca1b31e3654a62e77f8ce741713b2c58a8757de32ee07dfaa1ac`.
Firma SHA1 `242c140c399ef3321235eded917322e53a7de686`, SHA256
`9e83eda7a6c6b6c1c358cb07f224b470dff69d23ad4a1097e47e544c600b6d8e`.
La versión1.0 está confirmada en el HTML vivo de Play. La1.2/build3 del
mirror tiene otra firma; se conserva para contraste, sin usar su método ni
atribuirle compatibilidad de Play. No se ejecutó ninguno de esos APK.

JADX1.5.6 fijado produjo31 errores generales. Ruta crítica Java completa
contrastada con su propia transcripción Java ejecutable: XXTEA delta772515655,
clave4669 y doble desplazamiento UTF16. Los componentes nativos son transporte;
no son necesarios para abrir el catálogo. No se afirma JNI/Android ejecutados.

| Muestra | Versión | Servidores | HTTPNetworks | SSLNetworks | Bytes | Campos no vacíos /únicos |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| res/raw/default_config.hs | 0 | 1 | 1 | 0 | 8652 | 9 /7 |
| GET real vigente | 2.3 | 15 | 3 | 1 | 370560 | 77 /29 |

Incluido SHA256 `2da9124c62562cb3fbc92b52fef41b8b10ba947e872d424df29fb45c995ba246`.
Remoto SHA256 `2d01368fee662eb0973d0b2ae4ac688448f303c058ba6685660a1722887ee117`.
Ambos documentos completos, con todos sus campos/secciones, iguales al Java
original y worker aislado. La CLI repitió el GET con okhttp/5.3.2 y devolvió
el mismo documento. Gateway con resultado real e HTTP interno simulado:
200,15/3/1,rawText34328bytes, igualdad completa.

```sh
python scripts/apk_analysis/zig_verify.py incluido.enc --runtime
python scripts/apk_analysis/zig_verify.py remoto.enc --runtime
python -m unittest tests.test_enaa_tunnel tests.test_zig_tunnel tests.test_cloud_c8_vpn_registry
```

**18 Python aprobadas** (8 Enaa,9 ZiG,1 registro), **166 Node aprobadas**,
0 skips. Referencia Java produce fixtures sintéticos de Unicode, emoji,
CRLF y documento completo, incluyendo raíz, servidores, HTTP y SSL, listas
opcionales y datos desconocidos. Se prueban errores de sobre/campo conocido,
claves duplicadas, límites, schemas, CLI fuera del repo, worker, agente/URL
exactos y ausencia de redirecciones. Casos Node: icono, catálogo, switch
persistente, DNS, redirects, sesión/cuota, paridad y rechazo de parcialidad o
pérdida de SSL. Regresiones del resto de fichas y de Enaa incluidas.

El transporte Node al proveedor y el HTTP interno son simulados. Descarga real
por Python; egress Node real, despliegue VPS y sesión VPN/Android pendientes.
No se introduce extensión nueva por el recurso.hs. No se certifica un perfil
exportado. Originales y muestra cifrada duraderos: IDs en manifest/handoff.
No se suben binarios, catálogos reales, entradas descifradas ni secretos a Git.
