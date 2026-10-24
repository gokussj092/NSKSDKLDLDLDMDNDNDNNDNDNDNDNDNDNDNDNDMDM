# NPV Cloud credentials, legacy envelopes, and secure Android dialogs

Scope: PR #96 only; no UI/UX changes, merge, VPS deploy, Play release or
Server VPN roster/news changes.

- Modern binary **NPVS** (signed, authenticated) continues to use canonical
  `npvs.py`. NPVS v5 app-key is password-free; NPVS v5 passphrase returns
  `PASSWORD_REQUIRED` or `AUTH_FAILED`. Mode 0 recipient requires a genuine
  private ECDH key; `PRIVATE_KEY_REQUIRED` is not a password prompt.
- Legacy **NPVT1/NPVTSUB1** comma/white-box exports run their historical
  `NPVTUNNEL.py` primitives only on exact legacy headers. The bridge emits
  full JSON rather than Telegram display text, which omitted array entries.
  An invalid modern signed NPVS tag, signature, recipient or password is NEVER
  retried with the legacy reader, to avoid cryptographic downgrades.
- Texts: five explicit `npvt://`, `npvt-ssh://`, `npvt-vless://`,
  `npvt-vmess://`, `npv://` routes use the new NPV strict decoder in
  isolated Cloud text worker. Original `dns://`/`npvs1:` stay available.
  Only `npvt-ssh://` was confirmed in the source APK; the other four
  prefixes are aliases, not evidence of other decryptable ciphers.
- Android reuses current `CloudPasswordDialog` and `HcProtectedImportDialog`;
  the UI component layout is unchanged. Formats `.ua`, `.npvs`, `.1ftnl`
  and `.tut` can prompt on exactly `PASSWORD_REQUIRED`; HTTP Custom keeps
  its existing password/HWID requirement inspection.
- Wrong password returns a dedicated localized error; HTTP Custom combined
  password/HWID failures remain combined when the authentication tag does not
  identify which secret is incorrect. Errors are never logged with credentials.
- The Cloud client must be rebuilt to send NPVS/1FTunnel credentials. A VPS
  update alone does not update APK routing or dialogs.
- Validate 239 frozen Android routes separately from C8-only `1ftnl`
  bot and Cloud overlay. Test C0, C2/C3/C4/C7, focused Python and Android
  instrumental tests, and real-device cancellation and wrong-credential UX.
