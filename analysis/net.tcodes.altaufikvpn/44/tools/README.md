# tools/ — ALTAUFIK VPN 5.01

Este expediente no necesita herramientas propias: el método (OpenSSL
Salted__ + EVP_BytesToKey/MD5 + AES-256-CBC) vive entero en el script
operativo `Altaufik_VPN.py`, y la investigación se hizo con
`strings` + androguard (ver DEPENDENCIES.md). No se copia el script
operativo a `analysis/` (ver MANIFEST.json: el script operativo no se
copia a este expediente; la copia prevista de integración vive en
`decoders/Python/apps/Altaufik_VPN/`).

Los tests de `tests/` importan el script operativo por ruta y usan
vectores sintéticos (ver `tests/fixtures/README.md`).
