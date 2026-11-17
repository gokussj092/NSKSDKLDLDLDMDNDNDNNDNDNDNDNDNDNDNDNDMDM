# Fixtures — GOOD VPN 3.0

Todos los fixtures de este expediente son SINTÉTICOS, generados con
claves de prueba del propio test (`TEST-ONLY-KEY-16`). No contienen
datos reales del catálogo, ni servidores reales, ni credenciales reales:
los hosts usan la red de documentación TEST-NET-3 (203.0.113.0/24, RFC
5737) y `example.org`. Un fixture sintético demuestra la lógica
implementada, NO prueba compatibilidad con una versión real ni
conectividad remota.

- `synthetic_catalog.json`: catálogo sintético con la estructura del
  formato GOOD VPN (`Version`, `Message`, `Servers`, `Networks`,
  `setOpenVPN`), 2 servidores y 2 redes, con los valores internos ya en
  claro (el Base64 interno y el cifrado real se prueban con round-trip
  en `test_method.py`).
