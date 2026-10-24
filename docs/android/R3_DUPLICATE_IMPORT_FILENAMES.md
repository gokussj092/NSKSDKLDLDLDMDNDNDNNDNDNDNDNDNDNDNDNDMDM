# R3 — Duplicated SAF filename suffixes

Only import routing was changed in PR #96, on branch
`feat/austroplus-vpn-13-0-1-decoders`. No JSON viewer, decoder engine,
catalog delivery, VPS deployment or app release changes.

## Purpose

File providers may expose the basename `config.hc (1)`, `config.hc(2)`
or `backup.sksrv.png (3)`; the prior end-of-filename suffix tests
rejected them. `config (1).hc` already worked and is unchanged.

`ImportFilenameNormalizer.forDetection` removes one final positive decimal
` (N)` or `(N)` counter (1–6 digits) for routing only, if an extension
precedes it. It never changes the SAF URI, original DISPLAY_NAME, original
file bytes, result filename, history or exported original content.

Both catalog detectors share the normalizer, and MainActivity applies it
when checking HC password/HWID requirements, NPVS failure messages and
routing the offline decoder. Cloud still uploads the original bytes using
an explicitly registered and validated format suffix. Unsupported files
are never mapped to a guess; compound suffixes and Unicode keep priority.

## Tests

`DuplicateImportFilenameInstrumentedTest` covers legacy/native, Cloud C8,
compound and Unicode suffixes, protected imports, preservation of original
bytes/names, and rejection of invalid/malformed counter strings.
Keep `CloudC8InputRoutesTest` and `PhaseA239CatalogInstrumentedTest`
as regressions. Device testing with Android Storage Access Framework
is recommended before distributing an APK.
