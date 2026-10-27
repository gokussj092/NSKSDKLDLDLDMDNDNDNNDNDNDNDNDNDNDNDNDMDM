"""Strict JSON parsing and replacement of existing value tokens only (lab use)."""
from __future__ import annotations

import json


def _unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('Duplicate JSON key; lossless editing is ambiguous')
        result[name] = value
    return result


def _reject_constant(_):
    raise ValueError('Non-finite JSON number')


DECODER = json.JSONDecoder(object_pairs_hook=_unique, parse_constant=_reject_constant)


def parse(raw: bytes):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                      parse_constant=_reject_constant)


def equal(left, right) -> bool:
    """JSON equality with exact types: False != 0, and True != 1."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(equal(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(equal(a, b) for a, b in zip(left, right))
    return left == right


def differences(left, right, path=()) -> list[tuple]:
    if type(left) is not type(right):
        return [path]
    if isinstance(left, dict) and left.keys() == right.keys():
        return [p for k in left for p in differences(left[k], right[k], path + (k,))]
    if isinstance(left, list) and len(left) == len(right):
        return [p for i, (a, b) in enumerate(zip(left, right))
                for p in differences(a, b, path + (i,))]
    return [] if equal(left, right) else [path]


def replace_values(raw: bytes, edits: dict[tuple, object]) -> bytes:
    """Keep every byte outside existing edited value spans, including escapes.

    No added/deleted keys, regex replacement, global reserialization, or
    duplicate-key guessing. Offsets refer to Unicode text; UTF-8 is lossless.
    """
    text = raw.decode('utf-8')
    parse(raw)
    spans = {}

    def whitespace(pos):
        while pos < len(text) and text[pos] in ' \t\r\n':
            pos += 1
        return pos

    def walk(pos, path):
        pos = whitespace(pos)
        start = pos
        if text[pos] == '{':
            pos = whitespace(pos + 1)
            if text[pos] != '}':
                while True:
                    key, pos = DECODER.raw_decode(text, pos)
                    pos = whitespace(pos)
                    if not isinstance(key, str) or text[pos] != ':':
                        raise ValueError('Invalid JSON object')
                    pos = whitespace(walk(pos + 1, path + (key,)))
                    if text[pos] == '}':
                        break
                    if text[pos] != ',':
                        raise ValueError('Invalid JSON separator')
                    pos = whitespace(pos + 1)
            pos += 1
        elif text[pos] == '[':
            pos, index = whitespace(pos + 1), 0
            if text[pos] != ']':
                while True:
                    pos = whitespace(walk(pos, path + (index,)))
                    index += 1
                    if text[pos] == ']':
                        break
                    if text[pos] != ',':
                        raise ValueError('Invalid JSON separator')
                    pos = whitespace(pos + 1)
            pos += 1
        else:
            _, pos = DECODER.raw_decode(text, pos)
        spans[path] = (start, pos)
        return pos

    walk(0, ())
    changes = []
    for path, value in edits.items():
        if path not in spans:
            raise ValueError('Cannot add unobserved JSON field')
        start, end = spans[path]
        token = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':'))
        changes.append((start, end, token))
    ordered = sorted(changes)
    if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
        raise ValueError('Overlapping JSON edits')
    for start, end, token in reversed(ordered):
        text = text[:start] + token + text[end:]
    result = text.encode('utf-8')
    parse(result)
    return result
