# Administrative identity and notification isolation

Backend branch: `ci/unity-ads-online-qa`.

## Identity

Owner/support escalation labels use **Ghost Developer**, including the web panel,
Admin source, current owner session identity and support-message author metadata.
Migration 016 normalizes existing owner author labels; read-time rendering also
normalizes legacy owner labels. Encrypted message text, user profiles, billing
records, credentials and staff identities other than the owner are unchanged.
This changes the current source/deployment, without rewriting Git history.

## Separate notification channels

| Audience | Store / endpoint | Delivery |
| --- | --- | --- |
| Public SP-DECODE announcements | durable public feed / V2 op 17 | Online FCM public topic, only deliberately published general announcements |
| A user's support, purchase or security event | account_notices / account notifications API | only that account's encrypted device tokens, matching event ID and kind |
| SP-DECODE Admin internal events | admin_notices / `/api/admin/notifications/inbox` | only the authenticated administrative recipient, separate encrypted token table and Firebase credentials |

Support messages/escalations no longer write to the public feed. Existing internal
disk/Redis notices are excluded from every client read. Under the durable store
lock, legacy entries move to `admin-quarantine.json` with canonical developer
labels before being removed from `feed.json`. The owner's private inbox imports
these IDs idempotently. The public Redis fallback is sanitized as well.
Already delivered phone notifications cannot be recalled by changing the server.

Current internal support events target the owner. A staff session cannot read an
owner event by changing an ID or request body. New registration and read endpoints
derive the recipient from the authenticated panel session, never from client IDs.
All mutations retain existing CSRF checks. Tokens are encrypted with a distinct
Admin key derivation and are not stored in the Online device table.

Admin FCM sends only to a concrete token, never to a topic or condition. It requires
a different Firebase project and service account; missing/reused credentials leave
the event in the private inbox without sending through Online. FCM payloads include
`restricted_package_name` for their exact Android package. No notification bodies,
credentials or user messages are copied into administrative pushes.

Firebase reference: https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages#AndroidConfig

## Deployment

```sh
spdecode update web ci/unity-ads-online-qa
spdecode commerce migrate
```

Migration 016 adds the private Admin tables and normalizes owner author labels. It
does not remove user messages, purchases, credits, streaks or existing Online tokens.

The optional Admin push environment variables are independent of Online:

```dotenv
CLOUD_ADMIN_FCM_PROJECT_ID=
CLOUD_ADMIN_FCM_SERVICE_ACCOUNT_JSON=
```

Use a **separate Firebase project** with Android package
`com.ghostdeveloper.spdecode.admin` and its own service-account JSON. Store the
actual JSON only in server secrets, never in Git, logs or the APK. The Compose
service passes these values through without falling back to `CLOUD_NOTICE_*`.
If they are absent, administrative pushes stay disabled and the private inbox
remains usable. The current Admin application has no Firebase Messaging SDK or
FCM receiver; this patch does not claim device push is operational. Its inbox
read route now uses the private endpoint. To add background push later, configure
that separate Firebase Android application, then register/unregister its token
through the authenticated private endpoint. Never subscribe Admin to the Online
topic or reuse Online's Android Firebase configuration.

Public announcements remain an explicit owner-only publishing action, labeled
as announcements to SP-DECODE users. That action is separate from the private
administrative inbox.

## Guests and verification

Streak account credentials are optional metadata inside HPKE. Guest file/text
decodes do not query account authentication or streak storage. Expired account
sessions and streak-database outages preserve a successful decoder result. No
account or reward enrollment is required for guest file/text/catalog use.

Tests use synthetic PostgreSQL accounts, device tokens, RSA keys and mocked FCM;
they verify recipient ownership, separate projects/packages, rejected credential
reuse, encrypted token isolation, legacy quarantine, owner alias, and successful
guest/expired-session decodes. No real user is sent a test notification. Production
deployment and real Admin Firebase credentials are not available in this workspace.
