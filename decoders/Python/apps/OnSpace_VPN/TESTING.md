# Comprobación puntual — OnSpace VPN 4.2 (25)

Fecha: **2026-10-22**. Descarga externa autorizada expresamente por el usuario.
Inspeccionados `ConfigUtil`, `ConfigUtil$1`, `ConfigUpdate$1`, `usrUdt$1`, `usrNm`,
`AESCrypt`, `Trululu`, `SocksHttpMainActivity.getSecretKey/loadServerData/Choco`
y `res/raw/dnsd_conf`. No se ejecuta la app ni su verificación de licencia.

| Fuente | Bytes cifrados | Versión | Registros | Campos procesados / no vacíos |
| --- | ---: | --- | ---: | ---: |
| Servidores HTTPS, HTTP 200 | 487344 | 1662 | 164 | 2624 / 698 |
| Usuarios HTTPS, HTTP 200 | 856 | 63 | 1 | 6 / 6 |
| Asset `config.json` | 2816 | 1 | 1 | 16 / 4 |
| Asset `flags/st.png` | 856 | 1 | 1 | 6 / 6 |

SHA-256 de ambas respuestas cifradas:

- Servidores: `fa3ef820c3912c28ddfc934da4d52a23deb7ea6fe8783605b3472c437c7a0d6d`
- Usuarios: `0f610ab876997e7e78064394c2b8fcf62b4d1d369357897fef4b52b53fb9d880`

Los cuatro JSON completos y todos los campos conocidos coinciden con el oracle
JDK de `onspace_vpn_oracle.java`. Los vectores públicos son exclusivamente
sintéticos y se regeneran con `python tests/golden/onspace_vpn_generate.py`.
La comparación real no utiliza el lector Python como referencia de cifrado.

El sobre dual real atraviesa el worker aislado con `isPartial:false` y conserva
ambos documentos íntegros. Sobre: **651016 bytes**; salida renderizada del worker:
**180385 bytes**. Otra descarga real con el CLI `--all` desde fuera del repositorio
coincide con ambos documentos de referencia. No se trunca ninguna fuente.

**3 pruebas nuevas Python, 2 regresiones puntuales Jireh y 26 web aprobadas**:

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_onspace_vpn -v
cd cloud/web
node --test tests/onspace-vpn-remote.test.mjs tests/server-vpn-catalog.test.mjs
```

Cubren los 16 campos de servidor y seis de usuario, Unicode/UTF-16, registros
duplicados, listas y metadatos/tipos/vacíos conservados; worker y CLI stdin;
rechazo de campos cifrados inválidos, claves JSON duplicadas, no finitos,
truncamiento, límites y fuente ausente/equivocada. Las dos regresiones Jireh
comprueban sus campos/rotación y catálogo completo con valores predeterminados.
Web comprueba fuentes exactas, DNS público fijado, TLS, rechazo de IP privadas y
redirecciones, sobre dual, fallo de una fuente sin éxito parcial, gateway con
sesión y validación de ambos documentos recibidos del worker.

Icono: WebP original exacto, 19808 bytes, 192×192. SHA-256 original
`28027f6dc6c6d0c3bd51fbdc1c0d3ca891d6b86592e9e6bf8a3f64ffa66b353d`.
PNG sin pérdida: 29822 bytes, SHA-256
`59a6de90b34c625913705585ed6e0f2115b661015c656d9a0c43fdd036a5b232`.
Los píxeles RGBA de ambos formatos son idénticos.

No se ejecutan suites completas por petición del usuario. HTTPS externo real
por Python; transporte Node y respuesta del worker HTTP controlados en pruebas,
con proceso aislado real comprobado aparte. No se afirma despliegue VPS, CI remota,
sesión VPN, ejecución Android ni importación de un perfil exportado. APK, binarios,
respuestas reales y resultados con cuentas quedan fuera de Git.
