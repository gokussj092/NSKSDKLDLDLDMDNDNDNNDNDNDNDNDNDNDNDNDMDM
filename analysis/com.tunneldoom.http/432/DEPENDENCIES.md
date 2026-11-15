# Executed dependencies

- CPython 3.12, standard library: fixed-source acquisition, input limits,
  private temporary files, hashing and sanitized reports (PSF).
- androguard 4.1.3: static Android manifest, certificate-block metadata and
  DEX instructions; no APK execution (Apache-2.0).
- PyCryptodome 3.23.0: existing AES field decoder (BSD/Public Domain).
- Temurin OpenJDK21: independent Java/JCA oracle (GPL-2.0 with Classpath Exception).
- The full installed Python distribution list from CI, including unused
  transitive dependencies, is in dependencies.lock.json. Not all are execution
  tools. No Frida, app instrumentation or dynamic target execution was used.
- Python distribution archive hashes and transitive license review are UNKNOWN,
  not invented. Reproduction must review those artifacts before deployment.

All own scripts used for this recheck are acquire.py and revalidate.py.
The shared canonical oracle is scripts/apk_analysis/tunneldoom_verify.py plus
tests/golden/tunneldoom_oracle.java; no divergent copy was introduced.
