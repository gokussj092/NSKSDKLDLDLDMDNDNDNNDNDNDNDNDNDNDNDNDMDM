#!/usr/bin/env bash
# TEMPORARY: stage the private fixture bundle outside the Git working tree.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="${1:-/tmp/spdecode-export-lab}"
mkdir -p "$dest"
for name in source_original export_rejected; do
  fixture="$root/fixtures/http_custom/$name.hc.b64"
  if [[ ! -f "$fixture" ]]; then
    echo "Missing private fixture: $fixture" >&2
    echo "Restore from SP_DECODE_TEMPORARY_EXPORT_LAB_COMPLETE.zip locally." >&2
    continue
  fi
  base64 -d "$fixture" > "$dest/$name.hc"
done
echo "Staged private samples at: $dest"
