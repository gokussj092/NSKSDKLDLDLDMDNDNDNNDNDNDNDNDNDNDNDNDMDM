# XXPICore Tunnel — Cloud catalog

Package `pro.xxpicore.tunnel`, version1.0.18/build118. Public updater catalog2.427:
64 servers,1240 networks;7837 encrypted fields. Entire document independently
equal to Java/JCA, CLI download and isolated Cloud worker. Nine real fields also
verified with the original isolated ARM64 primitives. No account credential is
required for the catalog.

The native seed, IV, salts, XXTEA, Threefish tweaks and invisible carrier match
Xhypher43. Reuses its unchanged cipher primitives and `renz.py`; XXPICore keeps
its own schema and fixed updater. Unknown JSON keys, empty strings and nulls
remain intact. Full evidence, own scripts, dependencies and synthetic tests:
[build118 dossier](../../../../analysis/pro.xxpicore.tunnel/118/ANALYSIS.md).

```sh
python decoders/Python/apps/XXPICore_Tunnel/server_catalog_decoder.py --download > /private/catalog.json
python decoders/Python/apps/XXPICore_Tunnel/server_catalog_decoder.py /private/catalog.enc
```

Only the Cloud catalog is proposed. No file/text/export support is advertised.
The included resource `res/a_/drlb` is passed to native mode3 (`decryptDex`),
not validated here as an included catalog. Node live egress is denied in this
environment; simulated HTTP using the real bytes passed. VPS deployment and
human review remain pending. Android builds were not started or awaited.
