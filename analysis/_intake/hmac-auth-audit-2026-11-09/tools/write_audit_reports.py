#!/usr/bin/env python3
"""Publish only sanitized audit metadata; never copy APKs, hooks or key material."""
import argparse,hashlib,json,platform,shutil,importlib.metadata as metadata
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
INTAKE='analysis/_intake/hmac-auth-audit-2026-11-09'
PROFILES=[('speicers','netfree.mx.store',123,'Speicers Pro VPN','104.1.20'),
          ('http-injector','com.evozi.injector',244,'HTTP Injector','6.5.0')]
def put(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(value if isinstance(value,str) else json.dumps(value,indent=2,ensure_ascii=False)+'\n')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args()
    deps=[dict(name='Python',version=platform.python_version(),source='https://python.org/',license='PSF-2.0'),
      dict(name='androguard',version=metadata.version('androguard'),source='https://github.com/androguard/androguard',license='Apache-2.0'),
      dict(name='loguru',version=metadata.version('loguru'),source='https://github.com/Delgan/loguru',license='MIT')]
    environment=sorted((dict(name=d.metadata['Name'],version=d.version) for d in metadata.distributions()),key=lambda d:d['name'].lower())
    common=ROOT/INTAKE/'dependencies.lock.json'
    put(common,dict(schemaVersion=1,platform='Linux x86_64 static research only',direct=deps,installedPythonEnvironment=environment,
      distributionHashes='UNKNOWN: existing environment package archives were not retained; installed versions are recorded. Not approved for unattended execution.'))
    for folder,pkg,build,name,version in PROFILES:
        private=a.private/folder;identity=json.loads((private/'identity.json').read_text());report=json.loads((private/'hmac-usage-summary.json').read_text())
        if identity['package']!=pkg or identity['versionCode']!=build or identity['versionName']!=version:raise ValueError('AUDIT_IDENTITY_MISMATCH')
        if report['baseApkSha256']!=identity['baseApkSha256'] or report['credentialMaterialExtracted'] or report['apkCodeExecuted']:raise ValueError('AUDIT_SCOPE_MISMATCH')
        dossier=ROOT/'analysis'/pkg/str(build)
        put(dossier/'generated/identity.json',identity);put(dossier/'generated/hmac-usage-summary.json',report)
        lock_ref=common.relative_to(ROOT).as_posix()
        put(dossier/'dependencies.lock.json',dict(schemaVersion=1,include=lock_ref,includeSha256=hashlib.sha256(common.read_bytes()).hexdigest(),direct=deps))
        auth=dict(status='UNCONFIRMED',scope='VPN connection authentication',algorithm=None,
          material_provenance_category='UNKNOWN',service_verifier_observed=False,secret_material_extracted=False,
          evidence='Static aggregate API/algorithm inventory only; no per-function input/output capture.',
          limits=['Algorithm markers and Mac API references do not establish authentication purpose.',
           'No service connection, key recovery, protocol impersonation or authentication bypass was attempted.'])
        sources=[f'{INTAKE}/tools/audit_hmac_usage.py',f'{INTAKE}/tools/test_audit_hmac_usage.py',f'{INTAKE}/tools/write_audit_reports.py']
        put(dossier/'MANIFEST.json',dict(schema_version=1,package_name=pkg,app_name=name,version_name=version,version_code=build,
          observed_at='2026-11-09',source_category='user-provided archive' if folder=='http-injector' else 'documented public mirror/build123',
          authorization_note='Static, aggregate cryptographic-usage audit only. No extraction of service authentication secrets, APK execution, connection attempts or third-party binary redistribution.',
          status='PARTIAL',targets=[dict(kind='connection_authentication_audit',status='PENDING',scope='Presence inventory completed; VPN authentication purpose unconfirmed; no keys recovered.')],
          connection_authentication=auth,inputs=identity,dependencies=[{**d,'lockfile':f'analysis/{pkg}/{build}/dependencies.lock.json'} for d in deps],
          tooling=[dict(name='Owned aggregate static audit',path=s,sha256=hashlib.sha256((ROOT/s).read_bytes()).hexdigest()) for s in sources],
          code_paths=sources+['AGENTS.md','analysis/METHOD_EVIDENCE_POLICY.md']+(['decoders/Python/apps/Speicers_Pro_VPN/README.md'] if folder=='speicers' else []),
          evidence_refs=[f'analysis/{pkg}/{build}/generated/identity.json',f'analysis/{pkg}/{build}/generated/hmac-usage-summary.json',f'analysis/{pkg}/{build}/tests/test_method.py'],
          limitations=auth['limits']+['APK certificate digest is not complete publisher-signature/provenance verification.','No automatic F7 adapter or runtime authentication behavior changed.'],
          network_requirements=['Acquisition from the documented HTTPS mirror only; static scan has no network access.'],
          manual_steps=['Use independent references and owner-provided fictional service credentials for any authorized authentication test.'],
          unresolved_questions=['Whether a service-authentication HMAC exists, its protocol role and its verifier remain unconfirmed.']))
        observation=('Speicers documentation already describes HMAC in the catalog/file-format path; that evidence is not VPN-connection authentication evidence.'
          if folder=='speicers' else 'Only82 methods are visible in the base DEX. Native markers are present; this inventory does not cover all application logic or establish how native/protected code behaves.')
        put(dossier/'ANALYSIS.md',f'''# {name} {version}/build{build} — HMAC usage audit

Scope: identify presence without collecting service authentication material. Package/build and SHA256 are in generated/identity.json. {observation}

Observed: {report['dexFiles']} DEX, {report['methodsVisited']} methods visited, {report['javaApiInvocationCounts']['macGetInstance']} Mac.getInstance references, {report['javaApiInvocationCounts']['macInit']} Mac.init references, {report['javaApiInvocationCounts']['macDoFinal']} Mac.doFinal references and {report['nativeFiles']} native libraries inspected for fixed algorithm markers. These are static counts, including dependency code. No execution or protocol-role assertion follows from their presence.

The scanner retains only fixed algorithm names, counts, hashes, identity and explicit uncertainty. It does not collect class/function operands, function inputs/outputs, private keys, tokens, generated HMAC secrets or decrypted VPN profiles. No hook or vendor APK/native code executed. No connection was made to a VPN/authentication endpoint.

`connection_authentication.status` remains UNCONFIRMED. No keys were extracted; no catalog, decoder, file export or service route was activated. The audit rule is documented in AGENTS.md and section2.2 of METHOD_EVIDENCE_POLICY.md; no new automatic CI gate or F7 execution is claimed.
''')
        put(dossier/'RESULTS.md',f'''# Results

Identity and aggregate static inventory completed for {name} build{build}. VPN-connection HMAC authentication remains UNCONFIRMED. {observation}

Two isolated scanner boundary tests passed: a fictional secret in DEX strings/instruction operands is absent from both report and stdout; altered input bytes are rejected before creating a report. These synthetic tests validate audit redaction/identity handling, not a real service authentication protocol. Schema checks for the sanitized dossier are reproducible offline. No real authentication keys, sessions or connections were tested.
''')
        put(dossier/'DEPENDENCIES.md','# Dependencies\n\n'+ '\n'.join(f'- {d["name"]} {d["version"]}: {d["source"]}, {d["license"]}.' for d in deps)+f'\n\nLinux x86_64; installed research environment and transitive versions are recorded once in {lock_ref}, referenced by path/SHA256 in the build lock. Existing distribution archives/checksums are UNKNOWN, not fabricated or approved for unattended execution. No third-party binary is committed. Standard-library zipfile/hashlib/json/importlib inspect data only. Speicers acquisition reuses analysis/com.tunneldoom.http/432/tools/acquire.py without modifying it.\n')
        mode='from-upload' if folder=='http-injector' else 'download-speicers'
        extra=' --upload "$UPLOAD_ZIP"' if folder=='http-injector' else ''
        put(dossier/'REPRODUCE.md',f'''# Reproduce from repository root

Use Python3.12.14 and the recorded research dependencies. Set PRIVATE_DIR to a restricted directory outside Git. For HTTP Injector, UPLOAD_ZIP refers to the original user archive. Do not commit input bytes.

```bash
python {INTAKE}/tools/audit_hmac_usage.py {mode} "$PRIVATE_DIR/{folder}"{extra}
python {INTAKE}/tools/audit_hmac_usage.py scan "$PRIVATE_DIR/{folder}"
python {INTAKE}/tools/test_audit_hmac_usage.py -v
python -m unittest discover -s analysis/{pkg}/{build}/tests -v
```

The Speicers recipe pins documented build123; it does not silently replace it with another version. Verify hashes in generated/identity.json. No server authentication probe, HMAC-key recovery or input/output hook is part of this recipe.
''')
        put(dossier/'tools/scan.py',f'''#!/usr/bin/env python3
"""Static metadata scan only; delegates to the preserved common tool."""
import subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Expected private sample directory')
    subprocess.run([sys.executable,str(ROOT/{INTAKE!r}/'tools/audit_hmac_usage.py'),'scan',sys.argv[1]],check=True)
''')
        put(dossier/'tests/test_method.py',f'''import json,unittest
from pathlib import Path
class AuditReportTests(unittest.TestCase):
    def test_identity_bound_inventory_has_no_authentication_success_claim(self):
        root=Path(__file__).resolve().parents[1]
        identity=json.loads((root/'generated/identity.json').read_text())
        report=json.loads((root/'generated/hmac-usage-summary.json').read_text())
        self.assertEqual(identity['package'],{pkg!r});self.assertEqual(identity['versionCode'],{build})
        self.assertEqual(report['baseApkSha256'],identity['baseApkSha256'])
        self.assertTrue(report['scanCompleted']);self.assertFalse(report['credentialMaterialExtracted'])
        self.assertFalse(report['apkCodeExecuted']);self.assertEqual(report['vpnConnectionAuthenticationHmac'],'UNCONFIRMED')
''')
        put(ROOT/'analysis'/pkg/'README.md',f'# {name}\n\n[Build {build}: HMAC usage audit]({build}/ANALYSIS.md). Static inventory only; connection authentication remains UNCONFIRMED. No authentication keys extracted.\n')
    print('Two sanitized HMAC audit dossiers written')
