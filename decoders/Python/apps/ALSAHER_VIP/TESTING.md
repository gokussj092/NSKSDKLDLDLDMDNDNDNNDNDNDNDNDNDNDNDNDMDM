# Validación ALSAHER VIP

- 9 pruebas Python del proveedor, expuestas también desde el expediente.
- 38 pruebas Node: ALSAHER, Halcon y regresiones del broker/contrato.
-Catálogos real incluido y remoto completos iguales a Java, CLI y worker.
-CLI descargó realmente el remoto vigente con su User-Agent original.
-Replay Node con bytes reales/HTTP simulado: contrato completo correcto.

```bash
python -m unittest discover -s tests -p test_alsaher_vip.py -v
node --test cloud/web/tests/alsaher-vip.test.mjs cloud/web/tests/halcon-r-net.test.mjs cloud/web/tests/server-vpn-provider.test.mjs cloud/web/tests/server-vpn-worker-contract.test.mjs
```

Fixtures sintéticos producidos por Java: Unicode, aliases, campos desconocidos,
tipos, HTTP/SSL/JSONsettings. Negativas: HTML, truncado, JSON plano, duplicados,
campos cifrados inválidos, listas parciales, límites, redirección, DNS privado,
HTTP fallido y Content-Encoding inesperado. Estado de switches ajenos preservado.

Sin Android ni espera de sus workflows. La conexión Node real del VPS sigue
pendiente porque el ejecutor devolvió REMOTE_NETWORK_DENIED. No se presenta ese
fallo de red como un fallo del catálogo, que Python sí descargó y abrió.
