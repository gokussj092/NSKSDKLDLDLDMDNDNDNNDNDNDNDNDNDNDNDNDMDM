# TunnelDOOM 4.3.2 — source correction

The build430 broker used panel.tunneldoom.space. The authorized build432
updater contains a different fixed GET literal: web.tunneldoom.space/config.json.
The recipe is read from the actual ConfigUpdateco.doInBackground DEX code;
it is not inferred from DNS, guessed aliases or a fallback host list.

Current proof is in generated/current-proof.json. The original distribution
archive, actual Android identity and certificate digest were checked before
requesting the fixed updater. No APK code ran. The entire downloaded catalog,
including every protected field and the rendered JSON, matched the independent
Java/JCA oracle. Binary inputs and connection data are never committed.

The installer previously rejected the exact APKPure distribution CDN
data.winudf.com. That exact host is now permitted; prefix/suffix impostors,
HTTP, credentials, fragments and arbitrary redirect destinations remain denied.

Catalog roster metadata is unchanged. The upstream URL is broker-private and
the correction applies on the next server download, without changing Android
catalog IDs or requiring an APK/AAB build. Deployment remains separate.

The certificate digest is provenance evidence, not a claim that APK signing
blocks were cryptographically verified. No current-build SKS export is claimed.
