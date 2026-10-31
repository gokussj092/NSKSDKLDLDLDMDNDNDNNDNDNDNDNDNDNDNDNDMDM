import copy
import importlib.util
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('rasp_gate',Path(__file__).resolve().parents[1]/'scripts/ci/rasp_release_gate.py')
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
class ReleaseEvidence(unittest.TestCase):
    def fixture(self):
        commit='a'*40
        return {'commit':commit,'devices':[{'physical':True,'manufacturer':f'OEM-{i%2}',
            'api':api,'channel':'play_internal' if i%2 else 'authorized_sideload',
            'candidateCommit':commit,'evidenceRef':'review://synthetic-fixture',
            'checks':dict.fromkeys(gate.CHECKS|{'ui_no_crash','policy_denied_without_crash'},True),'falsePositives':0,
            'baselineP95Ms':100,'candidateP95Ms':110,'maxRegressionPercent':15,
            **dict.fromkeys(('cpuBudgetPass','ramBudgetPass','batteryBudgetPass','signerVerified'),True)}
            for i,api in enumerate([24,28,33,36])],
            'staging':{'candidateCommit':commit,'evidenceRef':'review://synthetic-fixture',**dict.fromkeys(gate.STAGING,True)},
            'ci':{'candidateCommit':commit,'runUrl':'https://example.invalid/run','success':True}}
    def test_missing_or_stale_evidence_rejected(self):
        for value in [{},None,[],self.fixture()]:
            self.assertTrue(gate.validate(value,'b'*40))
    def test_complete_synthetic_matrix_and_specific_regressions(self):
        v=self.fixture();self.assertEqual(gate.validate(v,'a'*40),[])
        for mutate in [lambda x:x['devices'][0].update(falsePositives=1),
            lambda x:x['devices'][1].update(candidateP95Ms=500),
            lambda x:x['devices'][2]['checks'].update(hook_recovery=False),
            lambda x:x['staging'].update(rollback_e2e=False)]:
            changed=copy.deepcopy(v);mutate(changed);self.assertTrue(gate.validate(changed,'a'*40))
if __name__=='__main__':unittest.main()
