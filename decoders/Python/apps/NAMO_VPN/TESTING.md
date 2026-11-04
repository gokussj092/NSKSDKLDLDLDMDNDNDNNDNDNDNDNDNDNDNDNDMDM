# Verificación

La descarga original real HTTP200/72881bytes, versión22.3, se abrió primero con
Java transcrito desde j44.m/n. Después se comparó todo el JSON con Python, CLI y
worker aislado. La descarga real por el adaptador operativo repitió el mismo
SHA256 y la comparación completa. Los registros reales permanecen fuera de Git.

10 pruebas Python y140 Node aprobadas. Incluyen vector ficticio generado con
Java, Unicode, cuatro longitudes de padding, claves desconocidas, ciphertext
corrupto/truncado/clave incorrecta, UTF8 inválido, duplicados/NaN, esquema,
límites, stdin/CLI, salida íntegra del worker, headers originales, redirects,
DNS privado y controles persistentes sin resetear decisiones previas.

```sh
python analysis/com.appxrayservice.namovpn/35/tools/run_checks.py /ruta/privada/checks
```

Node se ejecuta desde `cloud/web`, con las fuentes e iconos del repositorio.
No requiere build Android. HTTP sintético demuestra contrato, no conectividad;
la evidencia real es la descarga Python separada. Falta transporte Node real en
el VPS y rollout del operador. XXTEA no autentica, no se certifica detección
universal de alteraciones válidas ni conexión de las cuentas VPN.

[Resultados y negativos conservados](../../../../analysis/com.appxrayservice.namovpn/35/RESULTS.md).
