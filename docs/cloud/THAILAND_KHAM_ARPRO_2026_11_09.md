# Thailand / KHAM / AR PRO — Cloud integration, 2026-11-09

Branch: feat/nuevas-integraciones. No main merge, VPS deployment or Android build.

| Application | Real observation | Branch behavior |
| --- | --- | --- |
| Thailand VPN 1.0.3/build3 | FIS200, RemoteConfig200, original catalog200/868048 bytes,373 servers, DELETE200 | Full catalog reader, dynamic source resolver, worker, gateway, panel controls and original PNG connected |
| KHAM VPN24/build24 | Original OkHttp4.12.0 GET200/60588 bytes,version144,17 servers/19 networks | Modified XXTEA and explicit Base64 fields, full reader, worker, gateway, controls and original PNG connected |
| AR PRO VPN2.0/build2 | Original updater HTTP200/195-byte HTML: Site Unavailable | Existing research retained and rechecked; original PNG card disabled, no remote route activated |

[Thailand dossier](../../analysis/thailand.vpn.globalvpn/3/ANALYSIS.md), [KHAM dossier](../../analysis/com.khamvpn.net/24/ANALYSIS.md), [AR PRO history and recheck](../../analysis/noob.arpro.vpn/2/ANALYSIS.md).

Whole real documents match independent references, both CLI inputs and child-isolated worker. KHAM's independent Java oracle also compares264 encoded fields. Unknown metadata and restrictions remain intact. No result truncation, no synthetic VPN servers and no automatic export certification. AR PRO's recovered embedded sample does not substitute for a real remote catalog.

## Automatic PNG normalization

All public icon responses now carry actual PNG bytes and the SHA256 of those bytes. Original raster assets are retained. Before npm dev/build/start, the server normalizes vendor WebP/JPEG/AVIF/GIF rasters to PNG and validates originals, without scaling. A bounded cached runtime fallback also handles a missing PNG or mislabeled raster. Existing valid PNG bytes retain their hashes. MD PROXY's actual PNG is committed; the Docker-only dwebp special case is replaced by the shared converter. sharp0.35.5 and transitive server dependencies are locked; Docker uses npm ci.

Catalog source floor81,76 visible cards, two new live routes and one pending card. Existing format counts, provider switches, maintenance controls, signing and Android versions are preserved. On the normal deployment with the provider-control volume mounted, the existing roster-fingerprint synchronizer automatically advances the effective version and invalidates installed caches. Higher configured versions and operator switches are preserved.

## Verification and limits

- 46 Python regressions passed (new readers, real worker, MD PROXY, NAMO, Ultra family).
- 6 AR PRO pending-source/research checks passed.
- Full web suite:698 passed,2 intentionally skipped,0 failed (700 total).
- 20 transport-auditor tests passed; new transport-only baseline hashes recorded.
- Production Next build passed. Local production-start smoke returned catalog200,icon200 and76 actual bundled PNGs; its initial503 was the expected V1-policy gate because the local test had no policy volume. The test now supplies a private default-policy directory, without changing application security. Actual Node transport from this environment remains unverified: Thailand REMOTE_PROVIDER_UNAVAILABLE, KHAM REMOTE_NETWORK_DENIED. Explicitly simulated HTTP replay with real downloaded bytes and actual worker results passed. Repeat the real Node transport on the target VPS before claiming deployment verification.
- Three canonical dossiers pass structural evidence validation. Public acquisition identities/certificates are recorded; full publisher APK-signature provenance was not established. No vendor APK/library/catalog/credentials are committed.

All own acquisition, deobfuscation, native-static analysis, probes, golden-vector generation, independent oracles and validation scripts are preserved under analysis/_intake/thailand-kham-arpro-2026-11-09/tools, including failed hypothesis revisions. Existing AR PRO scripts/results remain retained. Research dependencies were not approved for unattended APK execution.

## GitHub follow-up

Catalog regressions passed on GitHub. The PR evidence gate exposed a missing Thailand protocol.py reference plus two earlier MD PROXY source edits without updated dossier links; these links are corrected. C1 exposed a synthetic test that assumed one heavy slot although the worker now has two; only the test fixture was corrected. Existing production worker/Ultra methods were preserved. See analysis/com.vpnproxymd.mdproxyvpn/29/CI_RECHECK_2026_11_09.md.
