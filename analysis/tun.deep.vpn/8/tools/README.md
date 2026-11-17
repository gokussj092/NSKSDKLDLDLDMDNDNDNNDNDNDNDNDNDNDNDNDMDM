# tools/ — DeepTune-VPN

Herramientas propias de este expediente. Contienen SOLO código
genérico sin claves de formato: el sobre Argon2id+AES-GCM recibe la
contraseña como parámetro — los tests usan claves de prueba
sintéticas (`TEST-ONLY-...`). Las contraseñas reales del método
viven únicamente en los scripts operativos
(`decoders/Python/apps/DeepTune_VPN/`) y nunca se copian aquí.

- `envelope.py`: abrir/cerrar sobres Base64(`salt[0:16] ||
  nonce[16:28] || ciphertext[28:]`), Argon2id + AES-256-GCM,
  AAD = salt. Misma construcción que el método real; los tests usan
  parámetros REDUCIDOS (t=1, m=8 KiB) solo para ir rápido — nunca
  parámetros reales con claves de prueba.
- Los scripts de investigación originales quedan en
  `~/workspace/analisis-apps/deeptune-vpn/work/`; no se copian al
  repo.
