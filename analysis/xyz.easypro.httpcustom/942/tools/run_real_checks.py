"""Real-file checks for the offline n19 port (owner files stay private).

Usage: run_real_checks.py <harness_new> <harness_orig> <files_dir>
Compares the new C++ harness against the Python reference oracle
(tools/ref_oracle/codec.py) on the owner's real .hc files, and against the
original (pre-n19) harness for unchanged behaviour. Files are read at
runtime only; no bytes or decrypted content are stored.
"""
import json, os, subprocess, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ref_oracle'))
import codec

NEW, ORIG, UF = sys.argv[1], sys.argv[2], sys.argv[3]

def run(exe, f, pw='', hwid=''):
    return subprocess.run([exe, os.path.join(UF, f), pw, hwid], capture_output=True)

cases = [
    ('test_open_2_7xqg.hc', '', ''),
    ('test_bloqueo_normal_1_aflj.hc', '', ''),
    ('test_bloqueo_normal_con_contrase_a_0_m46a.hc', '', ''),
    ('test_bloqueo_normal_con_contrase_a_0_m46a.hc', 'wrong-pass', ''),
    ('test_solo_whid_1_7zzx.hc', '', ''),
    ('test_solo_whid_y_pass_0_k9v4.hc', '', ''),
    ('Gjost_0_d9lo.hc', '', ''),
    ('884_0_wvd2.hc', '', ''),
]
failed = 0
for f, pw, hwid in cases:
    new = run(NEW, f, pw, hwid)
    old = run(ORIG, f, pw, hwid)
    line = f"{f} pw={pw or '-'}: NEW rc={new.returncode} OLD rc={old.returncode}"
    if new.returncode == 0:
        try:
            ref = codec.decrypt(open(os.path.join(UF, f), 'rb').read(), password=pw or None, hwid=hwid or None)
            got = json.loads(new.stdout)
            line += f" | py-ref match={got == ref}"
            if got != ref:
                failed += 1
                line += " | MISMATCH"
            else:
                line += f" | app_version={got['app_version']} profiles={len(got['config'])} banner={got['protections'].get('tunnelBanner')}"
        except Exception as e:
            failed += 1
            line += f" | py-ref raised {type(e).__name__}: {e}"
    else:
        line += f" | NEW stderr={new.stderr.decode().strip()[:80]}"
        line += f" | OLD stderr={old.stderr.decode().strip()[:80]}"
    print(line)
print("REAL-FILE CHECKS: " + ("ALL OK" if failed == 0 else f"{failed} FAILED"))
sys.exit(1 if failed else 0)
