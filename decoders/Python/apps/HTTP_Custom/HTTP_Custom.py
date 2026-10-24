#!/usr/bin/env python3
"""Application-named launcher; implementation lives in file_decoder.py."""
if __package__:
    from .file_decoder import main, run
else:
    from file_decoder import main, run

if __name__ == "__main__":
    raise SystemExit(main())
