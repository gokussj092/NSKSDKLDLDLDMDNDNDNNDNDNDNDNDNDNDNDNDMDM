# Decryption streak: verified local days and rolling rewards

Online branch: `ci/unity-ads-online-qa`. Daily activity is still recorded only
by the existing gateway hook after a successful bound file/text decode. Failed,
anonymous decodes and catalog downloads do not count.

## Calendar and clock integrity

- Production date/time comes from PostgreSQL `now()`, formatted by the server in
  the account's IANA time zone. The app displays the returned `today`; it does not
  derive progress, date highlights or rewards from the phone's wall clock.
- Authenticated `POST /api/account/streak` accepts only `{timeZone}`. The first
  validated zone is fixed to the account. Later phone/date/zone changes cannot
  move its reward calendar. Traveling does not silently reset the account zone.
- No HTTP operation accepts a day, counter, reward claim or account id from the
  client. Time-zone setup never increments the streak or grants a credit.
- One successful decode day per account is counted, across all linked devices.
  Row/account locks and the unique credit-ledger job id guard retries. Future
  stored dates or a server-clock rollback do not increment or reset the row.
- Server test clocks are dependency-injection parameters only; no route forwards
  client dates into them. DST is handled as calendar days, not 24-hour timers.

## Rewards and existing data

Every seven consecutive successful days grants exactly **one APK analysis
credit**, including runs that begin midweek. Starting a new seven-day block does
not reset the total streak. Missing a calendar day resets only the active run;
previously granted credits remain. There is no business cap at 7, 22 or 100 days.

Migration `015_streak_calendar.sql` adds calendar/reward metadata without deleting
existing totals, weekly flags or ledger rows. Legacy last-count timestamps retain
the original server timestamp. Initializing a local zone converts that baseline,
without recording another decode. Existing weekly grants are recognized by their
deterministic ledger ids; migration does not immediately pay a second prize.
Historical pending progress is carried conservatively, at most six unawarded days.

The chest is presentation/replay only: tapping it never calls a grant endpoint.
Celebration acknowledgement is scoped to account + server reward id, rather than
using the phone's current UTC week. The account balance is read after the streak
so an observed new reward has already been committed to the same credit ledger.

## Android presentation and assets

The profile card includes the verified local date, gold/purple progress, checked
completed days, the actual dates of the current seven-day block and a colorful animated chest
above day seven. Completed circles retain their numbers with a gold fill and a
small check; the path fills between verified completed days. The prize is hidden
until the earned chest opens. Profile snapshots refresh every 30 seconds
while on that page. Other account sections retain their existing behavior.

- Days 0–99: `racha-fuego-naranja.gif`.
- Day 100 onward: `racha-fuego-violeta.gif`; 101, 105, etc. keep increasing.
- The two supplied transparent GIFs are copied unchanged (512 × 512, 16 frames).
- Existing closed/open chest animations are retained.
- Cloud builds explicitly whitelist these four UI GIFs in `prepareCloudAssets`.
  The signed APK validation checks their presence and exact source hashes.
  No decoder vault material is added to the APK.

## Deployment and verification

```sh
spdecode update web ci/unity-ads-online-qa
spdecode commerce migrate
```

The explicit `commerce migrate` step applies migration 015 using the newly built
web image. Do not omit it: updating the web image alone does not migrate the
database. No new secret or worker-resource change is needed. Install the signed
Online APK too.
The VPS was not accessed by this patch.

Tests cover UTC compatibility, local midnight, DST repeated hours, immutable
zones, rejected client dates/claims, repeated-day idempotency, missed days,
legacy rewards and 105 simulated days yielding 15 credits. These are synthetic
server tests, not a claim of 105 real days or a device UI test.


## Follow-up: first-day attribution and local reminders (2026-11-17)

The decoder transport key and the optional biometric account-deletion key are
independent. Looking up the transport key in `account_device_keys` silently found
no account, so successful decodes could leave the counter at zero. Decodes now
carry the current account bearer **inside the HPKE-encrypted body**. The gateway
strips it before payload validation/provider/worker dispatch and validates the
account session only after a successful decode with nonempty output. A missing,
expired or revoked account session never awards a day, and never breaks the
decoder. Phone dates/counters/account IDs are not accepted. The verified streak
is returned with the decode to refresh local reminder state immediately.

The first verified decode counts day 1; four decodes on that same date still count
one day. HTTP Custom combined reference decoding also records a day on actual
success, never for a downloaded locked file or a request for credentials.
Previously unassociated decodes cannot safely be retroactively credited. After
updating **both server and APK**, perform another successful signed-in decode.
No new schema or secret is required beyond the existing migration 015.

`StreakReminderWorker` runs locally via WorkManager, without network constraints
or FCM. It checks for inactivity in the evening (20:00–22:59 in the account zone),
at most once per calendar day. A confirmed successful decode cancels today's
notification and moves the next check to the following evening. Logout clears
its state and scheduled work; notification opt-out cancels it. System permission,
legal consent and the existing notification preference are respected. Texts are
localized in all 14 app languages and reveal no prize.

Within a boot, reminder time advances from the last verified server timestamp
using elapsed realtime, so changing the phone clock does not move it. After a
reboot, only reminder timing may use the phone clock until the next account sync;
this never changes progress or rewards. Android can defer background work; these
are reminders, not exact alarms or guaranteed delivery after force-stop.
