# SP-DECODE Harness — Online UI and transfers

Branch: `ci/unity-ads-online-qa`. This patch preserves the analysis engine,
Yamada's support/watcher implementation, V2 authentication and result ZIP contents.
The existing decoder result viewers are unchanged.

## Behavior

- The analysis tab always identifies itself as **SP-DECODE Harness**, in every language.
- The import card shows the server's available credits, including zero. Pricing remains
  in the store. Reserving/charging/refunding credits still happens exclusively on the server.
- The file name and size appear during preparation and upload. Android reads the declared
  application label from APK resources (or base.apk in an APKS) without executing code.
  If a label cannot be resolved, the readable file name is used; JSON null never becomes a title.
- A single live card distinguishes preparation, upload, validation, queue, analysis,
  review, completion, partial completion and failure. Queue/review do not display an
  invented progress percentage. Subphases come from the actual server phaseCode.
- History rows open a detail sheet with source name, size, status, time and the ZIP
  download action. Completed results keep their verified local ZIP and can be exported
  again. Cached history and new local exports are scoped to the signed-in account.
  Signing out does not delete existing files or replace encryption keys.
- Yamada's avatar comes from the enabled staff profile selected by the existing support
  assignment rule. The preflight returns only `{name, role, avatar}`, never staff credentials.
  A missing avatar uses the existing neutral account icon; no synthetic portrait is used.

## Shared transfer preference

Existing preference, unchanged: `spdecode-catalog-sync / download-by-chunks`.
Settings now describe both catalog downloads and APK uploads. The selected value is
snapshotted when a file is queued; changing Settings applies to the next transfer.

- **Normal:** consecutive encrypted V2 upload frames, with no artificial delay.
- **Chunks:** the existing conservative 4.5-second interval between accepted frames.

Both use the existing server-negotiated frames (at most 2 MiB), SHA-256 acknowledgments,
HPKE/device/account authentication and durable encrypted checkpoints. Normal is a
continuous transfer, not a new 150 MB HPKE request: it does not increase protocol limits
or introduce a plaintext upload endpoint. Catalog download behavior is preserved.

## Notices from Muse / the watcher

Continue using the existing authenticated bot event endpoint:
`POST /api/v2/app-analysis/{jobId}/events` with the existing bot authorization.
No new secret or support thread is needed. Send real supported event codes when the
stage changes, and optional real progressPercent according to the existing API contract.
The client reads phaseCode/progressPercent/updatedAt from V2 status operation 29.

The UI recognizes metadata inspection, bytecode inspection/recovery/decompilation,
native libraries, method decoding/evidence correlation, catalog building and result
preparation. QUEUED_FOR_ANALYSIS and AWAITING_HUMAN override any stale prior phase;
terminal status always overrides the last in-progress event. Heartbeats do not claim
that results are ready. The patch does not change the watcher or send support messages.

## Installation and verification

Build the existing Online release workflow with its persistent signing secrets and R8.
Version remains 1.1.29 (44); no new keystore is generated. JVM tests cover null/fallback
names, status precedence and transfer pacing. Server integration tests exercise zero
credits, paid-start rejection, public staff avatar and the existing encrypted upload,
ZIP download and original-input access contracts.

Server update (needed for public avatar and readable zero-credit balance):

```sh
spdecode update web ci/unity-ads-online-qa
```

No new secret, volume, database migration or worker resource change is required.
The VPS was not accessed from this workspace. Device checks after installation:
queue a file in each transfer mode, reopen the app during upload/analysis, wait for
real watcher stage changes, and export a completed history ZIP twice. The same local
ZIP remains exportable when its server link expires, while signed in to its account.
