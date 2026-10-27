#!/usr/bin/env bash
# TEMPORARY / PRIVATE. Stage the owner-supplied encrypted samples OUTSIDE git.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 /private/SP_DECODE_TEMPORARY_EXPORT_LAB_COMPLETE.zip [/tmp/spdecode-export-lab]" >&2
  exit 2
fi

archive="$1"
destination="${2:-/tmp/spdecode-export-lab}"
[[ -r "$archive" ]] || { echo "ZIP not found or unreadable: $archive" >&2; exit 2; }
mkdir -p "$destination"
chmod 0700 "$destination"

unzip -p "$archive" fixtures/http_custom/source_original.hc > "$destination/source_original.hc"
unzip -p "$archive" fixtures/http_custom/export_rejected.hc > "$destination/export_rejected.hc"
chmod 0600 "$destination/"*.hc

printf '%s  %s\n' \
  '167593e228e10c3eaa98333198f0c1c946f328b7b99ab2ef574bc429576ca4ba' "$destination/source_original.hc" \
  '78d257386e9a50cc4548f44df0d67cdb37526941952ebcf490a66f6d74ee6f6f' "$destination/export_rejected.hc" \
  | sha256sum -c -
echo "Private fixtures staged outside Git at: $destination"
