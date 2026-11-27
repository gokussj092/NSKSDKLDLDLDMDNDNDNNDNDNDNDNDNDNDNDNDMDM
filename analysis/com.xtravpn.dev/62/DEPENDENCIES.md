# XtraVPN — revisión de conexión

Estado: PARTIAL. Se conecta código aportado sin modificar su algoritmo ni atribuir una descarga remota nueva.

Registro detallado: [DEPENDENCIES.md](../../platform/supplied-integrations/2026-11-14/DEPENDENCIES.md).

Fuente y límites originales: [XtraVPN](../../../decoders/Python/apps/XtraVPN/README.md).

Reproducir la comprobación de importación y binding, sin red:

```bash
python analysis/platform/supplied-integrations/2026-11-14/tools/verify_provider.py xtravpn
```

Las pruebas de broker, worker aislado y regresión se ejecutan desde el expediente compartido. Las muestras faltantes y bloqueos se mantienen explícitos; esta comprobación no certifica al proveedor.

---

## Executed dependencies — re-verificación 2026-11-27

- CPython 3.12.3, standard library: decoder runtime and tests (PSF).
- The XtraVPN decoder is stdlib-only (XXTEA, AES via its own
  implementation); no PyCryptodome/`cryptography` needed for the
  re-verification runs.
- androguard (analyst, APK manifest/certificate/DEX checks) and the
  Dalvik `Sk`/`hj` emulator (`evidencia/xtra-emu.py`, batch 15):
  versions UNKNOWN here, not invented.
- Python distribution archive hashes and transitive license review are
  UNKNOWN, not invented. Reproduction must review those artifacts before
  deployment.
