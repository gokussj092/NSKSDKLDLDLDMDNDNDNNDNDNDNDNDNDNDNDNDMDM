#!/usr/bin/env python3
"""Save reviewed metadata, dependencies and reproducibility without private profiles."""
import argparse
import datetime
import hashlib
import json
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[4]
DOSSIER=Path(__file__).resolve().parent.parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('private',type=Path)
    args=p.parse_args();private=args.private
    inv=json.loads((private/'unpacked/inventory.json').read_text())
    verification=json.loads((private/'verification.json').read_text())
    recovery=json.loads((private/'recovery.json').read_text())
    resources=json.loads((private/'resources-report.json').read_text())
    real_node=json.loads((private/'node-real.json').read_text())
    replay=json.loads((private/'node-replay.json').read_text())
    checks=json.loads((private/'checks/checks.json').read_text())
    assert all(x['exit_code']==0 for x in checks)
    python_log=(private/'checks/python.log').read_text()
    node_log=(private/'checks/node.log').read_text()
    python_count=int(re.search(r'Ran (\d+) tests',python_log)[1])
    node_count=int(re.search(r'ℹ tests (\d+)',node_log)[1])
    assert 'ℹ fail 0' in node_log and '\nOK\n' in python_log
    generated=DOSSIER/'generated';generated.mkdir(exist_ok=True)
    selected=[e for e in inv['entries'] if e['path'] in ('assets/LICENSE','assets/Licence.bat','assets/config.json',
              'assets/flags/config.png','assets/flags/usr.png') or e['path'].startswith('lib/')]
    write_json(generated/'input_inventory.json',{**{k:v for k,v in inv.items() if k!='entries'},'entries':selected})
    for name,value in [('verification',verification),('recovery',recovery),('resources',resources),
                       ('census',json.loads((private/'census.json').read_text())),('node-real',real_node),('node-replay',replay)]:
        write_json(generated/(name+'.json'),value)
    summary={'python':{'tests':python_count,'passed':python_count,'command':checks[0]['arguments']},
             'node':{'tests':node_count,'passed':node_count,'command':checks[1]['arguments']},
             'realPythonDownload':True,'jcaWholeDocumentEqual':True,'isolatedWorkerWholeDocumentEqual':True,
             'nodeTransport':real_node,'nodeReplay':replay,'androidBuildRun':False,'merged':False,'deployed':False}
    write_json(generated/'checks.json',summary)
    lock=json.loads((DOSSIER/'dependencies.lock.json').read_text())
    for path in ('decoders/Python/apps/HTTP_FenixVPN/codec.py','decoders/Python/apps/HTTP_FenixVPN/field_names.json'):
        if not any(x['path']==path for x in lock['shared_scripts']):
            lock['shared_scripts'].append({'path':path,'sha256':sha(ROOT/path)})
    write_json(DOSSIER/'dependencies.lock.json',lock)
    tooling=[]
    for path in sorted((DOSSIER/'tools').rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts:
            tooling.append({'path':str(path.relative_to(ROOT)),'sha256':sha(path),
                            'version':'2' if path.name in ('verify.py','set_constants.py') else '1',
                            'kind':'historical_revision_patch' if path.suffix=='.patch' else 'project_research_script',
                            'license':'project_owned; automatic Phase7 approval pending'})
    manifest={'schema_version':1,'package_name':'com.doriaxvip.tunnel','app_name':'Genis VPN',
              'version_name':'2.2.6','version_code':76,'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source_category':'owner_requested_public_store_app; APKPure binary acquisition',
              'authorization_note':'Owner requested manual catalog research and Cloud implementation. No APK redistribution, Android modification or service authentication bypass.',
              'status':'VERIFIED','verification_level':'VERIFIED_REAL','rollout_status':'NOT_DEPLOYED_NODE_VPS_TRANSPORT_PENDING',
              'targets':[{'kind':'catalog','method':'genis-vpn','status':'VERIFIED_REAL',
                          'remote_version':verification['remote']['version'],'server_count':84},
                         {'kind':'catalog','method':'included_users','status':'VERIFIED_OFFLINE_ONLY','user_count':1,
                          'note':'Bundled users document; not claimed as a remote source or mixed into remote output.'},
                         {'kind':'files','status':'NOT_INVESTIGATED'},{'kind':'text','status':'NOT_INVESTIGATED'},
                         {'kind':'export','status':'NOT_CERTIFIED'}],
              'inputs':[{'type':'XAPK','bytes':inv['bundleBytes'],'sha256':inv['bundleSha256'],
                         'source':'https://d.apkpure.com/b/XAPK/com.doriaxvip.tunnel?version=latest&nc=arm64-v8a&sv=23'},
                        {'type':'base_APK','sha256':inv['metadata']['baseSha256']},
                        {'type':'remote_encrypted_catalog',**recovery['remote']}],
              'tooling':tooling,'dependencies':[{'id':x['id'],'version':x['version'],'source':x['source'],
                            'license':x['license'],'license_review':x['license_review'],'lockfile':'dependencies.lock.json'}
                            for x in lock['python_packages']],
              'runtime_dependencies':lock['environment'],'shared_tools':lock['shared_scripts'],
              'code_paths':{'codec':'decoders/Python/apps/Genis_VPN/codec.py',
                            'cli':'decoders/Python/apps/Genis_VPN/server_catalog_decoder.py',
                            'broker':'cloud/web/lib/server-vpn-provider.mjs',
                            'gateway_contract':'cloud/web/lib/c3-gateway.mjs',
                            'worker':'cloud/workers/python/catalog_vpn_bridge.py',
                            'worker_isolation':'cloud/workers/python/engine.py',
                            'catalog':'cloud/web/lib/server-vpn-catalog.mjs',
                            'controls':'cloud/web/lib/c12-provider-controls.mjs',
                            'tests':'cloud/web/tests/genis-vpn.test.mjs'},
              'evidence_refs':['ANALYSIS.md','REPRODUCE.md','RESULTS.md','DEPENDENCIES.md','dependencies.lock.json',
                               'generated/input_inventory.json','generated/recovery.json','generated/verification.json',
                               'generated/resources.json','generated/census.json','generated/checks.json',
                               'generated/node-real.json','generated/node-replay.json','tests/test_catalog.py'],
              'limitations':['CBC has no authentication tag; correctness is not authenticity.',
                             'Original Java JSON keys/types preserved; empty optional strings stay empty instead of UI ERROR sentinels.',
                             'JADX exited3 with14 errors; relevant recovered routines and full real documents independently checked with JCA.',
                             'APKPure binary is2.2.6/build76; no claim of latest Google Play build.',
                             'Node real transport unavailable in this executor; offline HTTP/DNS replay explicitly simulated.',
                             'Certificate scheme presence/fingerprints only; no full apksigner verification.',
                             'No standalone file/text format, unlocked export, Android change, merge or deploy.'],
              'network_requirements':['Public fixed GitHub updater via HTTPS, normal TLS and public IPv4.',
                                      'No HTTP Authorization, session renewal or external secret files required for this updater.'],
              'manual_steps':['Validate real Node broker transport on VPS before rollout.',
                              'Keep any higher configured catalog version monotonic when deploying.',
                              'Review licenses and central registry before automatic Phase7 reuse.'],
              'unresolved_questions':['No separate remote users updater established; bundled document only.',
                                      'Automatic license registry and evidence CI enforcement remain pending.']}
    write_json(DOSSIER/'MANIFEST.json',manifest)
    (DOSSIER/'RESULTS.md').write_text(f'''# Resultados — Genis VPN 2.2.6 / build 76

**VERIFIED_REAL para catálogo remoto; transporte Node/VPS pendiente, sin despliegue.**

| Entrada real | Versión | Perfiles | Campos CBC no vacíos | Campos vacíos | JCA / CLI / worker completos |
| --- | --- | --- | --- | --- | --- |
| Catálogo remoto, HTTP 200 | 1114 | 84 servidores | 658 | 241 | Iguales |
| Configuración incluida | 1 | 1 servidor | 8 | 3 | Iguales |
| Usuarios incluidos | 1 | 1 usuario | 7 | 0 | Iguales; no se anuncia descarga remota |

El JSON remoto tiene {verification['remote']['outputBytes']} bytes y SHA256 `{verification['remote']['outputSha256']}`. Se conserva privado, fuera de Git. No se reemplaza la descarga remota por ninguno de los incluidos.

Suite actual: **{python_count} Python + {node_count} Node, todas aprobadas**. Incluye vectores JCA ficticios, CLI, worker aislado, metadatos completos, campos nuevos, vacíos, errores de Base64/HTML/truncado, claves duplicadas, tipos inválidos, redirecciones, DNS privado, switches y gateway autenticado. El test HTTP de gateway usa bytes/JSON ficticios y red simulada; no acredita conectividad real.

Python operativo descargó y descifró el documento real. Node real: `REMOTE_NETWORK_DENIED` en este ejecutor. Replay Node con bytes reales y resultado del worker real: `SIMULATED_HTTP_REAL_BYTES`, una petición, JSON completo igual. Debe repetirse el transporte Node real en VPS antes del rollout.

Catálogo Cloud: piso 69, 65 fichas, 256 formatos; versiones superiores configuradas y decisiones previas de operadores conservadas. Icono launcher original WEBP convertido a PNG sin cambiar sus píxeles. Constantes de formato inline en backend. No se editaron ni compilaron componentes Android, no hubo merge/deploy y no se certificó exportación unlocked.
''')
    print(json.dumps({'status':'VERIFIED_REAL','python':python_count,'node':node_count,'tools':len(tooling),'packages':len(lock['python_packages'])}))


if __name__=='__main__':main()
