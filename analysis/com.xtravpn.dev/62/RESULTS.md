# XtraVPN — revisión de conexión

Estado: PARTIAL. Se conecta código aportado sin modificar su algoritmo ni atribuir una descarga remota nueva.

Registro detallado: [RESULTS.md](../../platform/supplied-integrations/2026-11-14/RESULTS.md).

Fuente y límites originales: [XtraVPN](../../../decoders/Python/apps/XtraVPN/README.md).

Reproducir la comprobación de importación y binding, sin red:

```bash
python analysis/platform/supplied-integrations/2026-11-14/tools/verify_provider.py xtravpn
```

Las pruebas de broker, worker aislado y regresión se ejecutan desde el expediente compartido. Las muestras faltantes y bloqueos se mantienen explícitos; esta comprobación no certifica al proveedor.

---

## Results — re-verificación 2026-11-27

| Check | Result |
| --- | --- |
| Asset `config.json` | Opens with `Pitingo2089`: Version 1.0.0, 1 server ("Tigo Panamá. Op-1") |
| Self-test | 8/8 OK (re-run 2026-11-27) |
| Key correction | One key `Pitingo2089` for asset + remote + texts; the AdMob ID is an ad unit, not a key — verified in smali (`Sk(17)`, `hj(6)`, `Ld2.run`) |
| Timeout correction | 10 000 ms in `Lv0.run()` (was documented as 5 000 ms) |
| `xtravpn://` text | Exists (paste dialog `x()`); `--text` opens the asset blob with `Pitingo2089` — VERIFIED_SYNTHETIC (no real link sample) |
| Fixed fallback key `23605c1568999d3a` | WORKS — verified with a synthetic custom code (was documented as dead) |
| Live catalog | v5.4.675, 178 servers, opened with `Pitingo2089` from the phone's `Config.json` — VERIFIED_REAL, per-device only; no broker possible; catalog NOT stored in the repo |
| Sig-config | HTTP 200, 473 bytes, still does not decrypt (honest failure) |
| `.sks` | Excluded by rule; no file decoder |
| Synthetic unit tests | `python3 analysis/com.xtravpn.dev/62/tests/test_xtravpn_136.py -v` — 6 tests, all OK |

## What was NOT verified

- No real `xtravpn://` link/blob sample exists; the text route is
  verified against the asset blob only.
- The live catalog cannot be re-fetched without the per-device custom
  code or the phone's `Config.json`.
- The sig-config still does not decrypt; SSH-password derivation
  indices could change if the provider republishes it.
