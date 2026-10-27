#!/usr/bin/env bash
# Stage verified private fixtures; reject an existing destination (no clobber).
set -euo pipefail
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo 'Usage: stage_private_fixtures.sh PRIVATE.zip [NEW_PRIVATE_DIRECTORY]' >&2
  exit 2
fi
python3 - "$1" "${2:-/tmp/spdecode-export-lab}" <<'PY'
import hashlib
import os
from pathlib import Path
import sys
import zipfile

expected = {
    'source_original.hc': '167593e228e10c3eaa98333198f0c1c946f328b7b99ab2ef574bc429576ca4ba',
    'export_rejected.hc': '78d257386e9a50cc4548f44df0d67cdb37526941952ebcf490a66f6d74ee6f6f',
}
try:
    blobs = {}
    with zipfile.ZipFile(sys.argv[1]) as archive:
        for name, digest in expected.items():
            member = 'fixtures/http_custom/' + name
            if archive.namelist().count(member) != 1:
                raise ValueError('Missing or ambiguous member')
            if archive.getinfo(member).file_size > 16 * 1024 * 1024:
                raise ValueError('Oversized member')
            data = archive.read(member)
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError('Fixture SHA-256 mismatch')
            blobs[name] = data
    destination = Path(sys.argv[2])
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    for name, data in blobs.items():
        fd = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
except (OSError, ValueError, KeyError, zipfile.BadZipFile):
    sys.exit('Staging failed: verify ZIP/hash and use a NEW destination. Originals not overwritten.')
print('Staged 2 SHA-256-verified private fixtures. Keep them outside Git.')
PY
