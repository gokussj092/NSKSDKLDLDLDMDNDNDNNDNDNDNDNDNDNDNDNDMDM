#!/usr/bin/env python3
"""One isolated, bounded compatible-export job. No credentials in arguments."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))


def main():
    try:
        suffix, source, destination = sys.argv[1:]
        incoming = sys.stdin.buffer.read(32769)
        if len(incoming) > 32768: raise ValueError('INPUT_LIMIT')
        request = json.loads(incoming)
        if set(request)-{'credentials','language'}: raise ValueError('SCHEMA')
        credentials = request.get('credentials') or {}
        language = request.get('language', 'es')
        if type(credentials) is not dict or language not in ('es','en'): raise ValueError('SCHEMA')
        raw = Path(source).read_bytes()
        if not 0 < len(raw) <= 8*1024*1024: raise ValueError('INPUT_LIMIT')
        if suffix == 'hc':
            from cloud.workers.python.exports.http_custom import export
        elif suffix == 'ehi':
            from cloud.workers.python.exports.injector import export
        elif suffix == 'npvs':
            from cloud.workers.python.exports.npv import export
        elif suffix == 'hat':
            from cloud.workers.python.exports.hat import export
        elif suffix == 'dark':
            from cloud.workers.python.exports.dark import decode, unlock_configuration
            def export(data, credentials, language):
                if credentials: raise ValueError('UNSUPPORTED_CREDENTIALS')
                return unlock_configuration(decode(data))
        else: raise ValueError('UNSUPPORTED_FORMAT')
        output = export(raw, credentials, language)
        if not 0 < len(output) <= 1024*1024:
            print('{"status":"unavailable","code":"EXPORT_TOO_LARGE"}')
            return 3
        fd = os.open(destination, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream: stream.write(output)
        print('{"status":"ready"}')
        return 0
    except Exception:
        # Never return exception text: some parsers include raw input values.
        print('{"status":"unavailable","code":"EXPORT_VARIANT_UNSUPPORTED"}')
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
