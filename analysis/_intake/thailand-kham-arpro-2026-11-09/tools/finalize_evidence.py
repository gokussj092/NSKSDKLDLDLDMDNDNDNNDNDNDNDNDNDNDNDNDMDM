#!/usr/bin/env python3
"""Write sanitized build dossiers from actual private observations; never copy catalogs/APKs."""
import argparse,hashlib,json,platform,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
INTAKE='analysis/_intake/thailand-kham-arpro-2026-11-09/tools'
PROFILES={
 'thailand.vpn.globalvpn':dict(build=3,name='Thailand VPN',decoder='Thailand_VPN',identifier='thailand-vpn',
  method='Firebase FIS → Remote Config serverUrl → GET /global_admin/api/server?package_name=thailand.vpn.globalvpn. Base64/UTF-8 contains the full Status/Servers/Settings document. No custom auth/Integrity token or secret HTTP header is required. Only the original globalvpn.uk source is accepted.',
  result='Real FIS200, RemoteConfig200, catalog200/868048 bytes, 373 servers; temporary installation DELETE200. The whole document equals independent Base64/JSON reference, CLI file/stdin and isolated worker. Node actual transport failed REMOTE_PROVIDER_UNAVAILABLE here; explicitly simulated HTTP replay with real bytes/worker result passed.',
  sources=['thailand/vpn/globalvpn/servers/ServerModule.java','thailand/vpn/globalvpn/servers/apis/ApiService.java','thailand/vpn/globalvpn/servers/Config.java','thailand/vpn/globalvpn/ext/_ExtensionsKt.java','thailand/vpn/globalvpn/viewModels/MainViewModel.java']),
 'com.khamvpn.net':dict(build=24,name='KHAM VPN',decoder='KHAM_VPN',identifier='kham-vpn',
  method='Original libapi-kham.so getter a supplies the public HTTPS updater; getter b supplies a static file-format constant. MainActivity.C → ek0.run → xm1.g: Base64 + modified XXTEA (delta772515655), little-endian words and stored plaintext length. Explicit g72.m Base64/UTF-8 fields are decoded exactly once; names/ports/unknown fields stay intact. Original OkHttp UA4.12.0 is preserved.',
  result='Real HTTP200/60588 bytes, version144, 17 servers/19 networks. Independent Java envelope oracle plus 264 Java-decoded fields equal the entire CLI file/stdin and isolated worker documents. Node actual transport failed REMOTE_NETWORK_DENIED here; explicitly simulated HTTP replay with real bytes/worker result passed.',
  sources=['com/khamvpn/net/MainDetail.java','com/khamvpn/net/MainActivity.java','defpackage/j72.java','defpackage/ek0.java','defpackage/xm1.java','defpackage/g72.java','defpackage/c42.java']),
 'noob.arpro.vpn':dict(build=2,name='AR PRO VPN',decoder=None,identifier='ar-pro-vpn',
  method='Static P60/O60 string recovery, libovpn3 JNI_OnLoad registration table and ARM64 native disassembly identify NoobCrypt.b mode5 as AES256-XTS (16-byte tweak, rotated/XOR-derived 64-byte format constant), mode0 as AES256-GCM (12-byte nonce/16-byte tag). The included noobdev.js opens to a 1-server/1-tweak document, metadata GCM authenticates, and DefUpdateURL is recovered. No native APK code was loaded or executed.',
  result='PENDING remote catalog: the original DefUpdateURL GET returns HTTP200,195-byte HTML containing Site Unavailable. The separate app-update endpoint also returned that page. This is not JSON/catalog success. No remote worker method or broker route is activated; only the original PNG card is added disabled. Embedded sample evidence does not certify remote compatibility.',
  sources=['com/noobdev/vpn/utils/preference/NoobCrypt.java','defpackage/P60.java','defpackage/C4170vq.java','defpackage/C0579Kz.java','com/noobdev/vpn/ARTunnelMain.java']),
}
def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n' if not isinstance(value,str) else value)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args()
    packages=json.loads((a.private/'python-toolchain.json').read_text())
    for pkg,profile in PROFILES.items():
        build=profile['build'];private=a.private/pkg;d=ROOT/'analysis'/pkg/str(build);identity=json.loads((private/'identity.json').read_text())
        legacy={}
        if pkg=='noob.arpro.vpn':
            for name in ('MANIFEST.json','ANALYSIS.md','RESULTS.md','REPRODUCE.md','DEPENDENCIES.md','dependencies.lock.json'):
                result=subprocess.run(['git','show',f'HEAD:analysis/{pkg}/{build}/{name}'],cwd=ROOT,capture_output=True,text=True)
                if result.returncode==0:legacy[name]=result.stdout
        write(d/'generated/identity.json',identity);write(d/'generated/download-proof.json',json.loads((private/'probe-summary.json').read_text()))
        write(d/'generated/icon-proof.json',json.loads((private/'icon-summary.json').read_text()))
        static=[]
        for name in profile['sources']:
            path=private/'jadx/sources'/name
            if path.exists():static.append(dict(path=name,sha256=digest(path)))
        write(d/'generated/static-proof.json',dict(apkCodeExecuted=False,nativeCodeExecuted=False,jadxVersion='1.5.6',
          jadxGlobalErrors={'com.khamvpn.net':26,'noob.arpro.vpn':119}.get(pkg),
          jadxGlobalComplete=pkg!='thailand.vpn.globalvpn',sources=static,
          note='Unbounded simultaneous JADX attempts exited137. Thailand full run interrupted after relevant classes; targeted JADX runs succeeded. KHAM bounded full run exit1/26 errors; AR PRO bounded full run exit1/119 errors. Relevant call paths were reviewed separately.'))
        sources={'Python':('https://python.org/','PSF-2.0'),'JADX':('https://github.com/skylot/jadx','Apache-2.0'),
         'OpenJDK':('https://openjdk.org/','GPL-2.0-with-Classpath-exception'),'Node.js':('https://nodejs.org/','MIT'),
         'Pillow':('https://python-pillow.org/','HPND'),'androguard':('https://github.com/androguard/androguard','Apache-2.0'),
         'cryptography':('https://cryptography.io/','Apache-2.0 OR BSD-3-Clause'),'capstone':('https://www.capstone-engine.org/','BSD-3-Clause'),
         'pyelftools':('https://github.com/eliben/pyelftools','Public-Domain'),'sharp':('https://sharp.pixelplumbing.com/','Apache-2.0')}
        versions={'Python':'3.12.14','OpenJDK':'21.0.13','Node.js':'24.22.1 local /22 CI','JADX':'1.5.6','sharp':'0.35.5'}
        versions.update({x['name']:x['version'] for x in packages if x['name'] in sources})
        dependencies=[dict(name=k,version=v,source=sources[k][0],license=sources[k][1],lockfile=f'analysis/{pkg}/{build}/dependencies.lock.json') for k,v in versions.items()]
        write(d/'dependencies.lock.json',dict(schemaVersion=1,platform='Linux x86_64 research /Android ARM64 static input',
          direct=dependencies,pythonEnvironment=packages,sharpVersions=json.loads((a.private/'sharp-versions.json').read_text()),
          serverLockfile='cloud/web/package-lock.json',jadxDistributionSha256='545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974',
          unavailableHashes='PyPI artifacts for the pre-existing research environment were not retained; installed versions/transitive inventory recorded, distribution checksums UNKNOWN. Re-review unpinned research distributions before automated reuse.'))
        paths=['cloud/web/lib/server-vpn-catalog.mjs',f'cloud/web/public/server-vpn-icons/{profile["identifier"]}.png']
        if profile['decoder']:
            paths += ['cloud/web/lib/server-vpn-provider.mjs','cloud/web/lib/c12-provider-controls.mjs','cloud/web/lib/c3-gateway.mjs',
              'cloud/workers/python/engine.py','cloud/workers/python/catalog_vpn_bridge.py',f'decoders/Python/apps/{profile["decoder"]}/codec.py',f'decoders/Python/apps/{profile["decoder"]}/server_catalog_decoder.py',
              'tests/test_thailand_kham_vpn.py','cloud/web/tests/thailand-kham.test.mjs','scripts/ci/catalog-download-baseline.json']
        if pkg=='thailand.vpn.globalvpn':paths+=['cloud/web/lib/thailand-firebase.mjs','decoders/Python/apps/Thailand_VPN/protocol.py']
        paths+=['cloud/web/lib/catalog-icons.mjs','cloud/web/lib/catalog-icon-converter.mjs','cloud/web/scripts/convert-catalog-icon.mjs','cloud/web/scripts/prepare-catalog-icons.mjs','cloud/web/Dockerfile','cloud/web/package.json','cloud/web/package-lock.json','cloud/web/tests/catalog-icons.test.mjs']
        write(d/'MANIFEST.json',dict(schema_version=1,package_name=pkg,app_name=profile['name'],version_name=identity['versionName'],version_code=build,
          observed_at='2026-11-09',source_category='public store listing and APKPure distribution mirror/static analysis',
          authorization_note='Owner requested public-catalog interoperability on feat/nuevas-integraciones. Read-only original requests; no APK execution/redistribution, authentication bypass or VPN account generation. Mirror signer certificate extracted; complete publisher signature/provenance not established.',
          status='PENDING' if pkg=='noob.arpro.vpn' else 'PARTIAL',targets=[dict(kind='catalog',status='PENDING' if pkg=='noob.arpro.vpn' else 'VERIFIED_REAL',scope=profile['result'])],
          inputs=identity,tooling=[dict(name='Shared owned intake/static/probe/oracle tools',path=INTAKE),dict(name='Build recipe',path=f'analysis/{pkg}/{build}/tools/reproduce.py'),dict(name='Independent Java XXTEA oracle',path='analysis/com.appxrayservice.namovpn/35/tools/CatalogOracle.java')],
          dependencies=dependencies,code_paths=paths,evidence_refs=[f'analysis/{pkg}/{build}/generated',f'analysis/{pkg}/{build}/tests/test_method.py'],
          limitations=['No Android build, phone import or live VPN connection was tested.','Actual Node/VPS network transport remains to verify; real Python requests and explicitly simulated Node replay are separate.','No main merge, VPS deployment or automatic publication.','No new file/text format or Unlocked export inferred.','Research dependencies remain subject to human review before automatic execution.'],
          network_requirements=['Original allowlisted HTTPS hosts; pinned TLS/DNS broker rejects private addresses and redirects.'],
          manual_steps=['Review all Actions/evidence and validate Node transport on the intended VPS before rollout.','The existing roster-fingerprint synchronizer advances the effective catalog version on the mounted control volume; preserve configured higher versions and provider switches.'],unresolved_questions=['AR PRO vendor source currently unavailable.'] if pkg=='noob.arpro.vpn' else ['Production Node transport on VPS pending.']))
        write(d/'ANALYSIS.md',f'# {profile["name"]} — build {build}\n\n{profile["method"]}\n\n{profile["result"]}\n\nObserved identity and hashes: [identity](generated/identity.json). Full real APK/catalog bytes and decoded credentials remain outside Git. All own tools are preserved in [{INTAKE}](../../_intake/thailand-kham-arpro-2026-11-09/tools); see static source hashes and original icon pixel comparison under generated/.\n\nThe manifest certificate is not complete APK signature verification. Whole-APK JADX errors are recorded; no claim of a clean full decompilation. Initial unrestricted parallel JADX processes were killed for memory; bounded sequential runs and targeted classes replaced them. Thailand DEX string inventory first hit an unpaired UTF16 surrogate; the script now writes escaped surrogates. AR PRO initial XTS hypothesis omitted native per-byte rotate-right2 and failed UTF8; the corrected static transcription opens the embedded document. These observations are not simulated network success.\n\nOnly original raster assets were used, converted to PNG with equal RGBA pixels. Automatic server startup/build conversion and bounded runtime fallback use pinned sharp; all icon responses and content hashes refer to actual PNG bytes. Existing MD PROXY PNG is now committed, replacing its Docker-only one-off conversion.\n')
        write(d/'RESULTS.md',f'# Results — {profile["name"]}\n\n{profile["result"]}\n\nSynthetic golden vectors prove parser/schema/negative handling only. Thailand/KHAM: 7 focused Python tests and 10 focused Node icon/provider tests initially passed; 698/700 full web tests passed,2 intentionally skipped,0 failed. Web production build passed. Final regression/CI results are recorded in docs/cloud/THAILAND_KHAM_ARPRO_2026_11_09.md. No live Android/VPS rollout is claimed.\n')
        write(d/'DEPENDENCIES.md','# Dependencies and actual tooling\n\n'+ '\n'.join(f'- {x["name"]} {x["version"]}: {x["source"]}, {x["license"]}.' for x in dependencies)+'\n\nLinux x86_64. Python/Java perform offline inventory and independent oracles; Pillow extracts original PNG pixels; capstone/pyelftools statically read native ELF; cryptography provides the separate AR PRO XTS/GCM reference. No third-party binaries are committed. Relevant versions and full installed Python environment are in dependencies.lock.json; unavailable distribution hashes are explicitly UNKNOWN. sharp0.35.5 and server transitive versions/integrities are pinned by cloud/web/package-lock.json.\n')
        write(d/'REPRODUCE.md',f'''# Reproduce from repository root

Set PRIVATE_DIR to a restricted directory outside the checkout; do not commit APKs, tokens or catalog data.
Use Python3.12.14 with versions in dependencies.lock.json, Java21.0.13, JADX1.5.6 (official zip hash in lock), Node22+ and npm ci in cloud/web.

```bash
python {INTAKE}/acquire.py {pkg} "$PRIVATE_DIR/{pkg}"
python {INTAKE}/inspect_apk.py "$PRIVATE_DIR/{pkg}/base.apk" "$PRIVATE_DIR/{pkg}"
python {INTAKE}/inspect_splits.py "$PRIVATE_DIR/{pkg}"
JAVA_OPTS='-Xmx1300m' jadx --no-res -j 2 -d "$PRIVATE_DIR/{pkg}/jadx" "$PRIVATE_DIR/{pkg}/base.apk"
```

JADX global errors are expected and must be reviewed, not hidden. Run one bounded decompilation at a time. Original acquisition source is d.apkpure.net/b/XAPK/{pkg}?version=latest; verify the returned identity against generated/identity.json before interpreting build-specific offsets.

KHAM: run resolve_kham_strings.py then probe_kham.py with its private folder. Thailand: run probe_thailand.py; the analytical FIS installation is deleted best effort. AR PRO: resolve_arpro_strings.py SOURCE OUTPUT, then recover_arpro.py PRIVATE_APP and probe_arpro.py PRIVATE_APP. The native file hash is checked before using offsets. A 195-byte HTML response is a failure, not a decoded catalog.

```bash
python {INTAKE}/make_fixtures.py
python -m unittest tests.test_thailand_kham_vpn -v
python {INTAKE}/verify_real.py "$PRIVATE_DIR"
node {INTAKE}/verify_node.mjs "$PRIVATE_DIR"
cd cloud/web
npm ci --ignore-scripts --no-audit --no-fund
npm run icons:prepare
node --test --test-concurrency=4 tests/*.test.mjs
npm run build
```

verify_real compares whole documents with Java/stdlib reference, both CLI inputs and isolated worker. verify_node labels real transport separately from simulated HTTP replay. generated/ stores only counts/hashes/status; original decoded profiles remain private. No production deployment is performed.
''')
        write(d/'tools/reproduce.py',f'''#!/usr/bin/env python3
"""Build recipe delegates to preserved common scripts; no vendor execution."""
import subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Expected private app directory')
    script={"probe_arpro.py" if pkg=="noob.arpro.vpn" else "probe_kham.py" if pkg=="com.khamvpn.net" else "probe_thailand.py"!r}
    subprocess.run([sys.executable,str(ROOT/{INTAKE!r}/script),sys.argv[1]],check=True)
''')
        if pkg!='noob.arpro.vpn':
            name='KhamTests' if pkg=='com.khamvpn.net' else 'ThailandTests'
            test=f'from tests.test_thailand_kham_vpn import {name}\n'
        else:
            test='''import json,unittest
from pathlib import Path
class PendingSourceTests(unittest.TestCase):
    def test_html200_is_not_catalog_success(self):
        d=json.loads((Path(__file__).resolve().parents[1]/'generated/download-proof.json').read_text())
        self.assertTrue(d['html']);self.assertTrue(d['siteUnavailable']);self.assertFalse(d['enabled']);self.assertFalse(d['remoteCatalogVerified'])
'''
        write(d/'tests/test_method.py',test)
        write(ROOT/'analysis'/pkg/'README.md',f'# {profile["name"]}\n\n[Build {build}]({build}/ANALYSIS.md): {"remote pending; source returns HTML" if pkg=="noob.arpro.vpn" else "real catalog verified; VPS Node transport pending"}.\n')
        if legacy:
            index=ROOT/'analysis'/pkg/'README.md'
            oldindex=subprocess.run(['git','show',f'HEAD:analysis/{pkg}/README.md'],cwd=ROOT,capture_output=True,text=True)
            if oldindex.returncode==0:write(index,oldindex.stdout+'\n\nRecheck 2026-11-09: original source still returns HTTP200 HTML195. PNG card added disabled; see build2 generated/download-proof.json and appended analysis.\n')
            fresh=json.loads((d/'MANIFEST.json').read_text());original=json.loads(legacy['MANIFEST.json'])
            original['latest_recheck_2026_11_09']={k:fresh[k] for k in ('observed_at','targets','evidence_refs','limitations')}
            original['public_catalog_changed']=True;original['enabled']=False
            original['code_paths']={**original.get('code_paths',{}),'recheck_2026_11_09':fresh['code_paths']}
            original['tooling']=original.get('tooling',[])+fresh['tooling']
            write(d/'MANIFEST.json',original)
            lock=json.loads(legacy['dependencies.lock.json']);lock['researchRecheck20261109']=json.loads((d/'dependencies.lock.json').read_text());write(d/'dependencies.lock.json',lock)
            for name in ('ANALYSIS.md','RESULTS.md','REPRODUCE.md','DEPENDENCIES.md'):
                current=(d/name).read_text();write(d/name,legacy[name]+'\n\n# Recheck 2026-11-09\n\n'+current)
        if profile['decoder']:write(ROOT/'decoders/Python/apps'/profile['decoder']/'README.md',f'# {profile["name"]}\n\n[Mandatory build dossier](../../../../analysis/{pkg}/{build}/ANALYSIS.md).\n\nComplete offline run() reader; network access only via explicit CLI download or fixed Cloud broker. No new file/text/Unlocked export inferred.\n')
    print('Three sanitized build dossiers written')
