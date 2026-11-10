# Verification

Local: 98 HC native cases; exact complete JSON equality for the authorized
36,840-byte HC sample; 85 NPV cases; 9 Python tests/17 subtests; 7 Offline
UI/import contracts. Real HC output is 17 Config fields and one Protections
field; no values are recorded.

Host tests passed with the dependencies pinned in dependencies.lock.json.
Android Actions compilation/signing is tracked independently. Physical
Android line/selection/theme checks and actual NPV link QA remain pending.
Source-only UI checks do not certify those device behaviors.
