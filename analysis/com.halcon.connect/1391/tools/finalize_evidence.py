#!/usr/bin/env python3
"""Refresh the public evidence manifest after the authorized real validation.

Reads only sanitized summaries and source/fixture files. Never reads private
recipes, real catalogs, credentials or APKs, and performs no network requests.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT/'analysis/com.halcon.connect/1391'

def main():
    m=json.loads((BASE/'MANIFEST.json').read_text())
    result=json.loads((BASE/'generated/real_catalog.summary.json').read_text())
    assert result['jca_cli_worker_full_document_equal'] and result['earlier_cli_real_download_full_document_equal']
    m.update(status='VERIFIED',code_integrated=True,integration_enabled=False,
      authorization_note='El propietario autorizó expresamente repetir el POST firmado original con el material incluido en la APK, para obtener y validar un catálogo real. No se autoriza redistribuir el APK; no se almacena en Git.',
      verification_scope='VERIFIED_REAL_PYTHON_CLI_JCA_ISOLATED_WORKER',
      production_deployment_verified=False,
      conditional_enablement='Both provisioned backend secrets, global Server VPN enabled and individual switch allowed')
    m['targets']=[{'id':'catalog','type':'catalog','extensions':[], 'status':'VERIFIED',
      'envelope':'VERIFIED_REAL','real_catalog':'635','servers':101,
      'remote_primary':'HTTP_200_ORIGINAL_AUTHORIZED_POST','remote_backup':'HTTP_404',
      'embedded':'EMPTY_OBJECT','node_real_transport':'NETWORK_UNAVAILABLE_HERE_VPS_PENDING'}]
    m['tooling']=[{'id':'halcon1391:'+p.stem,'path':p.relative_to(ROOT).as_posix(),
      'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
      'purpose':'manual research, reproducibility, real verification or retained historical revision',
      'approval':'UNREVIEWED_FOR_AUTOMATIC_PHASE_7'} for p in sorted((BASE/'tools').rglob('*'))
      if p.suffix in {'.py','.java','.mjs'}]
    m['code_paths']={'operational_decoder':'decoders/Python/apps/Halcon_R_Net/codec.py',
      'catalog_cli':'decoders/Python/apps/Halcon_R_Net/server_catalog_decoder.py',
      'catalog_broker':'cloud/web/lib/server-vpn-provider.mjs',
      'updater_protocol':'cloud/web/lib/halcon-protocol.mjs',
      'worker':'cloud/workers/python/catalog_vpn_bridge.py',
      'worker_isolation':'cloud/workers/python/engine.py',
      'public_metadata':'cloud/web/lib/server-vpn-catalog.mjs',
      'worker_contract':'cloud/web/lib/c3-gateway.mjs',
      'provider_controls':'cloud/web/lib/c12-provider-controls.mjs',
      'deployment':'cloud/compose.yaml',
      'tests':['tests/test_halcon_r_net.py','cloud/web/tests/halcon-r-net.test.mjs']}
    m['runtime_source_hashes']=[{'path':p,'sha256':hashlib.sha256((ROOT/p).read_bytes()).hexdigest()}
      for p in ['decoders/Python/apps/Halcon_R_Net/codec.py',
                'decoders/Python/apps/Halcon_R_Net/server_catalog_decoder.py',
                'cloud/web/lib/halcon-protocol.mjs']]
    m['evidence_refs']+=['generated/primary.summary.json','generated/real_catalog.summary.json',
      'tools/verify_real.py','tools/replay_real.mjs','../../../tests/test_halcon_r_net.py']
    m['evidence_refs']=list(dict.fromkeys(m['evidence_refs']))
    m['limitations']=['Node direct broker returned REMOTE_NETWORK_DENIED in this executor; actual Node/VPS transport unverified.',
      'Android/Termux not executed; no Play-original signature comparison; latest official build not certified.',
      'No new file/text/export format claimed; no VIP/payment/account endpoints tested.',
      'JADX DEX1 had22 errors; relevant DEX2 completed successfully.',
      'Third-party license review/automatic Phase7 approval remain separate and pending.']
    m['network_requirements']=['Authorized fixed original POST with real provisioned signing secret; no redirects.',
      'Public backup404 is historical failure, never substituted for main response.',
      'Real Node/VPS validation still required.']
    m['manual_steps']=['Provision both real variables from private verified recipe/env artifact; preserve existing env and switches.',
      'Deploy only after owner instruction and test real Node path on VPS; no automatic merge/deploy in this change.']
    m['unresolved_questions']=['Actual Node/VPS transport and Android physical verification.',
      'Latest official build and exact Play mirror signature equivalence.']
    m['secret_consumers']={'SPDECODE_HALCON_REQUEST_SECRET':['web updater','Python catalog download CLI'],
      'SPDECODE_HALCON_CATALOG_PASSWORD':['web configuration readiness','Halcon-only worker child','Python CLI']}
    m['fixtures']=[{'path':p.relative_to(BASE).as_posix(),'type':'SYNTHETIC',
      'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted((BASE/'tests/fixtures').iterdir())]
    m['tests']={'python':22,'node':33,'result':'PASS',
      'independent_oracle':'OpenJDK17 JCA, complete real635/101 JSON equal to production CLI and isolated worker',
      'actual_downloads':'Research probe POST HTTP200 plus production Python CLI download, both real',
      'node_transport':'Real attempt failed environment network validation; real-bytes replay with mocked HTTP passed'}
    m['icon']={'source':'res/mipmap-xxxhdpi-v4/ic_launcher.webp','width':192,'height':192,
      'source_sha256':'4fef8deb94cf12ff617f61cf034b249e71ee7984fd5ce7a70aba919103552db9',
      'png_sha256':'859825df9e151d9b77039cc7f4a42b75feb3b9ea823999fa567ec823a173f143',
      'png_bytes':71433,'conversion':'Pillow PNG; original pixels verified identical'}
    node={'id':'runtime:node','name':'Node.js','version':'24.22.1','type':'runtime',
      'source':'https://nodejs.org/','license':'MIT and bundled components; NEEDS_REVIEW',
      'lockfile':'analysis/com.halcon.connect/1391/dependencies.lock.json',
      'used_by':'Node broker/contract tests and real-bytes replay; builtin modules only'}
    m['dependencies']=[d for d in m['dependencies'] if d['id']!=node['id']]+[node]
    (BASE/'MANIFEST.json').write_text(json.dumps(m,ensure_ascii=False,indent=2)+'\n')
    lock=json.loads((BASE/'dependencies.lock.json').read_text())
    lock['node']=node
    lock['pillow_bundled_webp']={'version':'1.6.0','source':'https://chromium.googlesource.com/webm/libwebp',
      'use':'original launcher format conversion','license_review':'NEEDS_REVIEW'}
    (BASE/'dependencies.lock.json').write_text(json.dumps(lock,ensure_ascii=False,indent=2)+'\n')
    print('Public manifest refreshed from verified sanitized summaries.')

if __name__=='__main__':main()
