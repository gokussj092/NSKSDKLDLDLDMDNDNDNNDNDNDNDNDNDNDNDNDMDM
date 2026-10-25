#!/usr/bin/env python3
"""Cloud/bot entrypoint for HTTP Door 5.0 .kyz, offline only."""
if __package__:
    from .codec import run, main
else:
    from codec import run, main

if __name__ == "__main__":
    raise SystemExit(main())
