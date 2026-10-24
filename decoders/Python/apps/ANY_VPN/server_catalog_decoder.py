#!/usr/bin/env python3
"""ANY VPN complete catalog; network I/O stays outside run()."""
if __package__:
    from .codec import decode_catalog, render, main
else:
    from codec import decode_catalog, render, main


def run(data: bytes) -> str:
    return render(decode_catalog(data))


if __name__ == "__main__":
    raise SystemExit(main())
