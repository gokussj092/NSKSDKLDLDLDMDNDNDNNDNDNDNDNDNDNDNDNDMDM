#!/usr/bin/env python3
"""Wolf build 13 NetworkList .wolf, preserving the historical Ultra reader."""
import argparse
from pathlib import Path
import sys
if __package__:
    from . import codec
else:
    import codec

def run(data: bytes) -> str:
    try:
        obj = codec.open_document(data, limit=codec.MAX_FILE_BYTES)
    except codec.EnvelopeError as error:
        root = Path(__file__).resolve().parents[4]
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from decoders.Python import ultra
        config = ultra.decrypt_ultra_file(data, '.wolf')
        if config is None:
            raise codec.DecodeError('Archivo Wolf no compatible.') from error
        return codec.render({'application': ultra.ULTRA_NAMES['.wolf'], 'extension': '.wolf', 'config': config})
    # Authenticated malformed JSON/fields must never fall back to another codec.
    return codec.render({'application': 'Wolf Custom VPN', 'extension': '.wolf',
                         'config': codec.decode_profile_document(obj)})

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', nargs='?', type=Path)
    args = parser.parse_args()
    try:
        if args.file:
            with args.file.open('rb') as stream:
                data = stream.read(codec.MAX_FILE_BYTES + 1)
        else:
            data = sys.stdin.buffer.read(codec.MAX_FILE_BYTES + 1)
        print(run(data))
        return 0
    except (ValueError, OSError, RecursionError):
        print('No se pudo leer el archivo Wolf completo.', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
