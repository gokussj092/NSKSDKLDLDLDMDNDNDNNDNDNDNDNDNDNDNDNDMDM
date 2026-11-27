# XtraVPN — revisión de conexión

Estado: PARTIAL. Se conecta código aportado sin modificar su algoritmo ni atribuir una descarga remota nueva.

Registro detallado: [REPRODUCE.md](../../platform/supplied-integrations/2026-11-14/REPRODUCE.md).

Fuente y límites originales: [XtraVPN](../../../decoders/Python/apps/XtraVPN/README.md).

Reproducir la comprobación de importación y binding, sin red:

```bash
python analysis/platform/supplied-integrations/2026-11-14/tools/verify_provider.py xtravpn
```

Las pruebas de broker, worker aislado y regresión se ejecutan desde el expediente compartido. Las muestras faltantes y bloqueos se mantienen explícitos; esta comprobación no certifica al proveedor.

---

## Reproduce — re-verificación 2026-11-27

From the repo root, with CPython 3.12 installed:

```bash
# 1. Self-test del script (asset + campos + XXTEA + sig-config).
python3 decoders/Python/apps/XtraVPN/XtraVPN.py --self-test
# Expected: self-test: 8/8 OK

# 2. Asset (config.json ya está en el repo, junto al script).
python3 decoders/Python/apps/XtraVPN/XtraVPN.py --asset
# Expected: Version 1.0.0, clave Pitingo2089, 1 servidor.

# 3. Texto xtravpn:// con el blob del asset.
python3 decoders/Python/apps/XtraVPN/XtraVPN.py --text \
  "xtravpn://$(cat decoders/Python/apps/XtraVPN/config.json)"
# Expected: Version 1.0.0, clave Pitingo2089, 1 servidor.

# 4. Synthetic-only unit tests (no network, no real data).
python3 analysis/com.xtravpn.dev/62/tests/test_xtravpn_136.py -v

# 5. Revalidation script (self-test + asset + text + custom-code sintético).
python3 analysis/com.xtravpn.dev/62/tools/revalidate_62.py
```

Notes:

- The live catalog (v5.4.675, 178 servers) cannot be re-fetched here:
  its URL lives inside a per-device custom code. The reproduction of
  the live result needs the phone's `Config.json` or the custom code +
  Android ID (see ANALYSIS.md). Do not invent a URL.
- The sig-config check needs network (`cdn.toolsp.site`) and is
  expected to fail to decrypt (honest failure, see ANALYSIS.md).
