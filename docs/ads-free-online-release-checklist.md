# SP-DECODE Online — Native account and ad-free release

Branch: `ci/unity-ads-online-qa`; version: `1.1.27 (42)`.

## Production rollout

The Android QA branch is **not** a production deployment. Before selling ad-free access, deploy the compatible web backend and apply `cloud/web/sql/003_ads_free.sql` to the SP-DECODE PostgreSQL database using a migration account and `ON_ERROR_STOP=1`. This additive migration is idempotent, creates the disabled `ads-free` product if absent, and does not overwrite administrator pricing.

Explicitly enable the product in the existing authenticated commercial admin panel after reviewing USD price and tax rules. The existing server settings `SPDECODE_STORE_ENABLED`, `SPDECODE_ACCOUNTS_ENABLED`, `SPDECODE_PAYMENTS_LIVE`, provider credentials, webhook secrets, and reviewed tax rules control checkout availability. Do not enable live payments until the provider webhook and mode separation pass integration QA.

## Entitlements

1. Android obtains products and provider availability from `GET /api/store/catalog`. The local display price is not a checkout authority.
2. An authenticated session requests `POST /api/store/quote` for the user's billing country and `POST /api/store/checkout` to open a validated hosted Stripe or PayPal checkout.
3. Only a verified provider webhook settles the order. A paid `ads-free` order creates a 30-day account entitlement with `expires_at`; renewals extend the active period and are serialized by account lock.
4. `GET /api/account` returns `adsFree.active` and `adsFree.expiresAt` for active, unexpired entitlements in the correct live/test payment mode. Refunds and disputes revoke their entitlements.
5. `ads-free` entitlements cannot be claimed as offline or API keys.

## Mobile release policy

- Account, Purchases, API, Security, Profile editing and Ad-free are separate native screens; no placeholder windows for unfinished password flows.
- Google Credential Manager and Android APIs stay in Kotlin/Java where platform bindings require them. C++/JNI validates profile input and server-derived ad-free entitlement time; backend authorizes the purchase.
- Unity LevelPlay checks account entitlement before initializing, loading or displaying ads, including QA every-file mode. The authenticated account state is refreshed on Activity resume and may be refreshed manually after payment.
- Existing native APK signer pinning is enforced on launch/resume. R8 minification and resource shrinking are on; native guards remain defense in depth and do not promise immunity to reverse engineering.
- Preserve the persistent signing keystore in GitHub Secrets. This QA must not emit an AAB or include Play-only updates.

## QA checklist

- Google sign-in, linked avatar/name/username; logout clears account and ad entitlement.
- Navigate from hamburger menu to independent full screens; hardware Back returns to correct destination.
- Edit profile and verify changes persist across app restart and locale changes.
- Check all 14 locales in portrait, landscape, large fonts, RTL and narrow devices.
- Check ad-free server price, tax quote, provider URL allowlist and pending/confirmed states.
- Verify live/test separation, successful webhook, renewal, expiry, refund and dispute.
- Verify signed APK, certificate pin, R8, 16-KB ELF alignment, native ABIs and absence of Play-only updater.
- Verify that unauthenticated/tampered/expired clients cannot mint or claim ad-free licenses.

**Activation gate:** no commercial ad-free purchases are live until the migration, backend deployment, administrator product enablement and end-to-end payment tests are complete.
