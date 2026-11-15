# Dependencies actually used

Local host: Python 3.12.14 / Unicode 15.0.0, g++ 14.2.0, Linux x86_64.
Mbed TLS 3.6.7 was compiled from the official, SHA-256-verified release;
Argon2 reference 20190702 from the pinned commit; nlohmann JSON 3.11.3
from its official single header. Sources, licenses, versions and available
hashes are in dependencies.lock.json. No third-party binaries are committed.

Python reference-only environment: PyCryptodome 3.23.0, argon2-cffi 25.1.0
and msgpack 1.1.1, with installed transitives frozen in the lock. Distribution
hashes were not retained and are recorded as unavailable, not invented.
The Python stdlib supplies Unicode classification, hashing and subprocesses.
NPV additionally uses system zlib (see lock). Source downloads require network;
all parity checks run locally without contacting third-party VPN services.

No new Android runtime dependency. Android continues to use the existing
CMake, NDK and Mbed TLS/Argon2 build declarations. UI uses Android TextView,
SpannableString, ScrollView and the existing Compose integration.
