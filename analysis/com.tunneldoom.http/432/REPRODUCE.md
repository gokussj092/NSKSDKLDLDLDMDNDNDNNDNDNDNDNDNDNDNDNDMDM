# Reproduction

Use Python 3.12 and JDK21 in a private disposable directory. Do not install or
execute the original application. Installed dependency versions from the actual
CI run are recorded in dependencies.lock.json; distribution hashes for Python
packages were not captured and must not be claimed.

    python -m pip install pycryptodome==3.23.0 androguard==4.1.3
    python -m unittest discover -s analysis/com.tunneldoom.http/432/tests -v
    python analysis/com.tunneldoom.http/432/tools/revalidate.py --report /tmp/tunneldoom-proof.json

The verifier accepts only the expected package, version432, prior certificate
digest, one actual updater-method literal and a complete live catalog matching
the independent JCA oracle. It removes private inputs with its temporary
directory and emits only identity metadata, hashes, counts and parity status.
A changed latest version or source fails explicitly; no guessed fallback runs.
