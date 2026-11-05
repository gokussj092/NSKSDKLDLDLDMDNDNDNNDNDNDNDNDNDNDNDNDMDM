# Analysis — 2026-11-05

Expected application ID: `com.tunneldoom.http`. Expected candidate versionName `4.3.2`, code `432`, **not yet independently verified**. Former build 430 used `https://panel.tunneldoom.space/config.json`, verified 26 October 2026. Previous Work observed that source no longer responded in its environment. The exact new updater URL is unknown.

Search sources: APKPure public package listing (indexed copies stale), AppBrain (4.3.0, 2026-10-28). Attempted direct download from this session using fixed APKPure XAPK endpoint; direct binary access failed due environment connectivity. No ZIP/manifest/signature/DEX from build432 has been inspected. 

A candidate may be downloaded by `tools/acquire.py` in a network-connected, private environment, but success requires XAPK manifest package/version match. **Archive manifest is untrusted input**: subsequent validation must inspect binary AndroidManifest.xml, compare signing certificate against previously observed signer SHA256 `12704504f5711f22d78ee436f38baeb90557c2fa72c4dfb281c766f59800461d`, and compare DEX updater instructions. No deployment or decoding change is authorized by this evidence.
