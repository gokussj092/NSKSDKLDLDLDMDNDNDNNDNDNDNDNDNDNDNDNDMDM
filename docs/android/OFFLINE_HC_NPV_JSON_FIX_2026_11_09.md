# Offline: HTTP Custom, NPV text and JSON

Work is confined to `feat/nuevas-integraciones` and the isolated Offline
variant. The online Python codecs, Cloud viewer, signing identity, package
and version are preserved.

- HTTP Custom: historical candidate decoding mirrors Python's UTF-8 ignore
  and Unicode predicates before printable/alphanumeric checks. The user's
  36,840-byte file now has complete C++/server dictionary equality. Existing
  HCCFG/HCX4 password/HWID/both and tamper coverage remains in the 98-case suite.
- NPV: preserve the five existing aliases, add server legacy DNS/standalone
  npvs1 entry points and propagate nested-field failures. The 85-case suite
  checks complete content, signed envelopes and negative inputs.
- JSON: a selectable Android TextView uses its own Layout line baselines to
  paint numbers; there are no independently measured number/code columns.
  LTR layout prevents Arabic/system RTL settings from reversing JSON.
  Horizontal scrolling keeps logical lines intact. No pagination or truncation.
  The viewport remains bounded to 150 rows while retaining the full text.
- Syntax: same dark palette as online (keys blue, strings green, numbers
  amber, booleans violet, null pink), with readable variants for light mode.
- Formatting: always parse and pretty-print objects/arrays with two-space
  indentation, including already multiline/large output and old history.
  Copy and export use that same representation. Strings containing payloads,
  escapes or embedded JSON stay strings and are not reinterpreted. Numbers
  are painted separately and never enter the clipboard or file.

No separate native result engine is introduced. Android's standard selection
provides movable selection handles and arbitrary copied ranges.

## Verification and remaining device checks

Local: 98 HC cases, 85 NPV cases, 7 existing offline UI/import contracts;
real HC file equality. Android compilation/signing is the existing Offline
Actions workflow and is tracked per commit. Device verification remains:
open the HC sample; compare JSON; select across lines; copy all; export and
reopen; scroll past line 150; check long lines and emoji/CJK/Arabic with large
font scale; check AMOLED/dark/light; paste actual NPV links.

Evidence with unknown exporter build retained under
`analysis/_intake/httpcustom-offline-20261109/` and
`analysis/_intake/npv-offline-text-20261109/`. No private configurations are
versioned. Unknown HCX4 11/n13 is still not claimed as supported.
