"""No-secret tests of the HPKE non-regression gate in the VPS operator.

Executes only the isolated shell functions with a fake Compose process; never
accesses VPS, remote Docker, real keyrings, actual environment or Git refs.
"""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/"cloud/infra/vps/spdecodectl").read_text(encoding="utf-8")
START=SOURCE.index("hpke_expected_before_update(){")
END=SOURCE.index("\nupdate(){",START)
FUNCTIONS=SOURCE[START:END]


class HPKEUpdateContract(unittest.TestCase):
    def run_case(self, env_text, state, *, post=None):
        with tempfile.TemporaryDirectory() as temp:
            env_file=Path(temp)/"cloud.env"
            env_file.write_text(env_text,encoding="utf-8")
            env_file.chmod(0o600)
            test=f"""set -euo pipefail
ENVFILE="{env_file}"
die() {{ echo "REJECTED" >&2; exit 41; }}
log() {{ :; }}
hpke_runtime_ids() {{ if [[ "$FAKE_HPKE_STATE" == ERROR ]]; then return 1; fi; printf '%s' "$FAKE_HPKE_STATE"; }}
{FUNCTIONS}
"""
            if post is None:
                test+='hpke_expected_before_update >/dev/null\n'
            else:
                test+=f'hpke_confirm_after_update "{post}" >/dev/null\n'
            env={**os.environ,"FAKE_HPKE_STATE":state}
            return subprocess.run(["bash","-c",test],env=env,capture_output=True,text=True,timeout=10)

    def test_active_keyring_survives_when_compose_env_is_persistent(self):
        state="896f195624217d42"
        self.assertEqual(self.run_case(
            'CLOUD_V2_HPKE_ENABLED=true\nCLOUD_V2_HPKE_KEYRING=synthetic-test-only\n',state
        ).returncode,0)
        self.assertEqual(self.run_case('',state,post=state).returncode,0)

    def test_active_hpke_rejects_missing_switch_or_keyring(self):
        state="896f195624217d42"
        for env in ('CLOUD_V2_HPKE_ENABLED=false\nCLOUD_V2_HPKE_KEYRING=placeholder\n',
                    'CLOUD_V2_HPKE_ENABLED=true\n',
                    ''):
            with self.subTest(env=env):
                self.assertNotEqual(self.run_case(env,state).returncode,0)

    def test_disabled_runtime_must_agree_with_declared_policy(self):
        self.assertEqual(self.run_case('CLOUD_V2_HPKE_ENABLED=false\n',"OFF").returncode,0)
        self.assertNotEqual(self.run_case('CLOUD_V2_HPKE_ENABLED=true\n',"OFF").returncode,0)

    def test_failure_to_inspect_runtime_must_fail_closed(self):
        self.assertNotEqual(self.run_case('CLOUD_V2_HPKE_ENABLED=true\n',"ERROR").returncode,0)

    def test_postflight_rejects_key_rotation_or_downgrade(self):
        baseline="896f195624217d42"
        for after in ("OFF","bbaadd0011223344","ERROR"):
            with self.subTest(state=after):
                self.assertNotEqual(self.run_case("",after,post=baseline).returncode,0)

    def test_update_verifies_before_git_reset_and_after_recreate(self):
        update=SOURCE[SOURCE.index("\nupdate(){"):SOURCE.index("\nset_env(){")]
        self.assertLess(update.index("hpke_expected_before_update"),update.index('sync_ref "$ref"'))
        self.assertIn('deploy "$kind" && {',update)
        self.assertIn('hpke_confirm_after_update "$hpke_before"',update)
        self.assertIn("restoring previous source and rebuilding",update)
        self.assertNotIn("CLOUD_V2_HPKE_KEYRING=",SOURCE[SOURCE.index("hpke_runtime_ids(){"):SOURCE.index("\nupdate(){")].split("hpke_expected_before_update(){")[0])

    def test_operator_shell_syntax(self):
        result=subprocess.run(["bash","-n",str(ROOT/"cloud/infra/vps/spdecodectl")],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__ == "__main__":
    unittest.main()
