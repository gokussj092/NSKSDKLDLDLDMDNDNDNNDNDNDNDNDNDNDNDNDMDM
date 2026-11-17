# Fixtures — MO VPN 1.0.6

Todos los fixtures de este expediente son SINTÉTICOS, generados con
claves de prueba del propio test (`TEST-ONLY-KEY-16`). No contienen
datos reales del catálogo, ni servidores reales, ni credenciales reales:
los hosts usan la red de documentación TEST-NET-3 (203.0.113.0/24, RFC
5737) y `example.org`. Un fixture sintético demuestra la lógica
implementada, NO prueba compatibilidad con una versión real ni
conectividad remota.

- `synthetic_catalog.json`: catálogo sintético con la estructura del
  formato MO VPN (`FileName`, `Servers`, `HTTPNetworks`, `SSLNetworks`),
  2 servidores y 2 redes, con los campos cifrados ya en claro (el
  cifrado real se prueba con round-trip en `test_method.py`).
