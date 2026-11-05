# External file import and verified catalog download modal (2026-11-04)

Branch: `feat/nuevas-integraciones`. No new decoder methods or APK release artifacts.
> **Plan futuro de escalabilidad (documentación, sin implementación):** [Catálogo Server VPN V2: chunks reanudables, barra y total reales, motor JSON .so, versiones visibles y QA](../cloud/CATALOG_SERVER_VPN_RESUMABLE_NATIVE_ENGINE_PLAN_2026_11_04.md). Este diseño no sustituye el comportamiento disponible en Android 1.1.27.


## Root cause and scope

`MainActivity` could process a WhatsApp/Telegram `ACTION_VIEW` /
`ACTION_SEND` before the asynchronously loaded `fileFormats` Compose state
contained a locally downloaded Cloud catalog. Only legacy APK routes were then
visible to the detector, leading to `unsupported_file` even when a supported
extension was already present in the encrypted catalog.

A second gap was that some providers deliver file URIs via `ClipData`
instead of `EXTRA_STREAM`.

## Resolution

- `ExternalImportUris` centralizes `ACTION_VIEW`, `ACTION_SEND`,
  `ACTION_SEND_MULTIPLE` and `ClipData` handling; the original URI is read via
  Android `ContentResolver`.
- Every Cloud file import loads the last authenticated local catalog snapshot
  **before checking the suffix**. `ImportFormatRouter` uses the validated local
  formats first, and permits only explicitly pinned historical Cloud suffix
  routes or the bundled registry when no valid local snapshot exists. It
  never guesses a format from MIME, arbitrary URI fragments, or file bytes.
- Startup hydrates the cached format list before processing the icon directory.
- The encrypted catalog cache remains the persistent source of truth; no decoder
  implementations or raw vendor secrets are downloaded into the APK.
- The native HTTPS request for catalog operation 10 sends genuine encrypted
  response-byte counts (HTTP body bytes) to the UI. `Content-Length` is the
  denominator only when actually provided. Otherwise the indeterminate
  indicator displays received MB without a fabricated percentage.
- The existing AMOLED color scheme is reused in a centered overlay. During
  download: title, progress indicator, MB received/total and Cancel. On success:
  only the title, saved-formats message and Finish.
- Cancel invalidates the native transfer generation and cancels the Kotlin job.
  Cancellation checks run before encrypted catalog metadata is activated;
  previously validated metadata is retained. New icons are saved under immutable
  SHA-256-derived cache keys instead of overwriting the previous snapshot's
  ID-keyed icons. Old encrypted icon caches remain readable. Native catalog read timeout is
  60 seconds **of inactivity per read**, not a total deadline; connection,
  memory and server limits remain finite.

## Regression tests added

`ExternalCatalogImportInstrumentedTest` checks VIEW data/ClipData,
SEND EXTRA_STREAM/ClipData, multi-file deduplication, a Cloud-only suffix
recognized from the downloaded snapshot during cold start, duplicate suffix
normalization, and rejection of mismatched suffixes without unsafe guessing.

## Required release QA (not claimed as executed)

1. Android 13-16, cold start and warm start, open the **same** supported
   configuration via WhatsApp, Telegram, the system Files provider, and the
   in-app picker; compare format result and Cloud request routing.
2. Repeat for a suffix only present in the latest downloaded catalog and for
   compound suffixes such as `.sksrv.png`.
3. Test a URI with no `DISPLAY_NAME`; it must not produce a speculative format
   or disclose any file contents to the wrong decoder.
4. With a throttled network, verify real byte increments, actual
   `Content-Length`-based percent when present, and no fabricated total
   when the server omits that header.
5. Cancel mid-stream and verify that the old local snapshot still detects
   files, and that the next manual catalog update can succeed.
6. Verify completed overlay dismisses to the same screen; the other
   languages must use their localized resources.

No live WhatsApp/Telegram provider test, emulator run, native C++ build, or
release APK compilation is represented by this document.
