# Fixtures — ALTAUFIK VPN 5.01

Todos SINTÉTICOS. Hosts en `203.0.113.0/24` (TEST-NET-3) y dominio
`example.org`. Ningún valor real de servidor, ninguna contraseña de
usuario, ninguna credencial: la única constante criptográfica es la
contraseña de formato `mtscrypt`, que ya vive en el script operativo
y es necesaria para descifrar cualquier catálogo de la familia tcodes.

- `synthetic_catalog.json` — catálogo plano sintético con la misma
  forma (Version, Servers, Tweaks) para probar el passthrough y la
  validación estructural. No es un catálogo real.
- El vector de sobre Salted__ sintético vive en el propio script
  operativo (`_SELF_TEST_VECTOR`, Version `99.9`) y se prueba en
  `test_method.py` sin copiarlo aquí.
