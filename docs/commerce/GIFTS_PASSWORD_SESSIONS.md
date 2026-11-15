# SP-DECODE Online — Persistent accounts, passwords and gift codes

Branch: `ci/unity-ads-online-qa`. Android version `1.1.27`, build `42`.

## Account and device security

- Android stores the Better Auth bearer session encrypted via an Android Keystore AES-GCM key. Only nonsecret identity preview data is cached encrypted for display while offline. Ad-free entitlements are **never** trusted from an offline cache.
- Better Auth rolling sessions last 90 days and refresh after 12 hours of regular authenticated requests. The account retains access unless the server revokes the session, the user signs out, or it expires after inactivity.
- Public display name/username/avatar changes and authorized public API IP changes require a valid session, but not a login less than 15 minutes old.
- Email/password registration is closed. A Google-linked account may add a first password through a server-only Better Auth `setPassword` call after a fresh Google-authenticated session (15-minute window). Existing passwords require the previous password through Better Auth `changePassword`; other sessions are revoked.
- Google Credential Manager and Android Keystore remain platform code; server authorization is authoritative. The optional Android 11+ fingerprint/device PIN gate protects the local account UI. **This device gate is not server MFA/TOTP**, does not create server tokens, and stores no biometric templates.
- An existing verified Google account with password may sign in using email/password. Public email/password account creation remains disabled, preventing duplicate unverified identities.
- Never transmit passwords, bearer tokens, gift codes or private configuration content to client diagnostics or analytics.

## Gift codes

The admin console has a **Códigos de regalo** page at `/admin/gifts`. Only authenticated administrators with mutation authorization may create or disable codes. A newly generated random 128-bit code is shown **once**; the database stores an HMAC-SHA256 digest keyed by the existing `SPDECODE_SHOP_TOKEN_KEY`.

The admin specifies a label, reward type (`credits`, `ads-free` or `offline-3`), amount or days, maximum number of distinct account redemptions (1–10000) and optional expiration. Users redeem via the native store screen, using `POST /api/store/redeem` with an authenticated session and code. The server validates the code, expiry, available uses and one-use-per-account constraint within a database transaction. A per-account attempt counter limits guesses to eight attempts per 15-minute window.

Successful redemption produces a separate zero-cost `gift` order (not a provider charge). Credits are appended to the immutable credit ledger; ad-free time extends the end of a current active entitlement; Offline creates a time-limited, claimable license with the existing three-device model. These grants use the current `SPDECODE_PAYMENTS_LIVE` mode to keep QA redemptions out of production.

Admin redemption history includes the **current** display name, username, photo/avatar and permanent account ID, plus when and which gift was used. Codes never appear in the list after initial creation. Disabled codes stop new redemptions without revoking previously granted gifts.

## Server rollout

No production deployment is performed automatically. After reviewing the QA branch, apply the migration through the existing commerce migration command; the runner now applies the existing `002_shop.sql`, additive `003_ads_free.sql` and additive `004_gifts.sql` under its commerce database advisory lock. All migrations are idempotent and do not activate real payment processors or modify administrator prices.

The admin shop now shows a dedicated ad-free product (30 days, server-controlled USD price). Activation requires real provider credentials and verified webhooks (Stripe/PayPal), tax configuration and the existing `SPDECODE_STORE_ENABLED` and product availability switches. **The ad-free product is disabled by default**; no live charge can be simulated by a gift order. Ad-free access is confirmed only by the authenticated server snapshot, paid webhook, or verified gift redemption.

## Verification matrix

1. Install the same-signed APK; confirm Google account and image/name/username persist on app restart. Observe that the drawer hides the email.
2. Edit profile after more than 15 minutes; no new login should be required. Verify username seven-day cooldown remains.
3. Add a password to a Google-only account; confirm recent Google reauth when required. Change it using the old password; a wrong old password must fail. Sign in using email and the configured password without creating another account.
4. Enable local fingerprint/PIN protection; verify account screens require device authentication on foreground re-entry and do not mint a different server session. Test device without configured secure lock.
5. Admin create a code with one use, one with multiple uses, a disabled and an expired code. Check concurrent claims, duplicate-account rejection and attempt throttling.
6. Redeem credit, ad-free (30, 60, 365 days) and Offline gifts. Verify account-bound ledger, expiration, API entitlements and admin recipient avatar, username and permanent ID.
7. Reconfirm that Unity Ads is suppressed only for active ad-free entitlements returned by the server. Refund/dispute/expiry of paid access revokes it.
8. Verify persistent signing cert, 14-localization support, R8, APK signature, GitHub artifact hash and absence of Play-only updater in the external APK.
