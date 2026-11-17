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
- APK analysis, including its completed result card and detail sheet, always uses the
  **SP-DECODE Harness** name and the existing `arnes.webp` icon. Support staff identity
  and profile photos are displayed only in support conversations.

## Support profile photos

Support reads resolve current photos by the original staff account id. Editing or
removing a profile photo updates old bubbles and the conversation list at the next
normal inbox refresh (12 seconds while open). Stored message snapshots, ciphertext,
names, read receipts and delivery behavior are preserved. Messages from deleted or
unidentifiable staff retain their recorded snapshot rather than borrowing another
agent's photo. Thread rows use the assigned agent, or the last responding agent on
older servers; they no longer swap to the user's photo after an outgoing message.

New Android clients request `X-SPDECODE-Support-Avatars: shared-v1`. The server sends
one copy of each photo in an account-scoped avatar map; the client resolves references
for the existing chat components. Other clients retain the compatible inline format.
This avoids multiplying a full-size photo across every historical reply. Only the
support inbox GET has a 4 MiB response cap; other account endpoints retain 256 KiB.
No new key, migration or change to the support bot/watcher is required.

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

V2 op 27 uses a dedicated authenticated upload budget (96 frames/minute per
session/device, 128/IP, 256 globally, 3600/day/device). Proof/replay validation
still runs first, and the gateway still validates the account, job, upload token,
size and SHA-256. Read-only ops 25/29/30 use the existing metadata quota; paid
start/finish and decoder operations retain their work quotas. This prevents
large uploads and status polling from exhausting the decoder's 10/minute budget.

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

Server update (needed for continuous uploads, public avatar and readable zero-credit balance):

```sh
spdecode update web ci/unity-ads-online-qa
```

No new secret, volume, database migration or worker resource change is required.
The VPS was not accessed from this workspace. Device checks after installation:
queue a file in each transfer mode, reopen the app during upload/analysis, wait for
real watcher stage changes, and export a completed history ZIP twice. The same local
ZIP remains exportable when its server link expires, while signed in to its account.
