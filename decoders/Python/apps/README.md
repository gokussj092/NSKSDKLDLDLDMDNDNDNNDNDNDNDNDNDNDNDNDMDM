# Decodificadores organizados por aplicación

Cada aplicación de este lote tiene su propia carpeta, con nombres
reconocibles y espacios representados mediante guiones bajos:

- `Nombre_de_la_App.py`: lector exclusivo del catálogo, cuando exista.
- `Nombre_de_la_App_archivos.py`: lector exclusivo de archivos o textos,
  cuando se haya identificado ese formato.
- `Nombre_de_la_App.png`: icono original extraído de la aplicación.
- `README.md`: uso, formatos, evidencia y límites de validación.

Los lectores son ejecutables independientes. Las muestras sintéticas y sus
productores se mantienen en `tests/golden`, y las pruebas en `tests`.

## Aplicaciones

| Aplicación | Catálogo | Archivos/textos | Icono y documentación |
| --- | --- | --- | --- |
| 24clan VPN Green 3.3 | [Script](24clan_VPN_Green/24clan_VPN_Green.py) | [.green](24clan_VPN_Green/24clan_VPN_Green_archivos.py) | [Carpeta](24clan_VPN_Green/README.md) |
