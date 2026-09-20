"""Canonical JSON for signing: sorted keys, separators (",", ":"), UTF-8.

Floats are rejected outright — money-grade determinism demands unambiguous
numbers (all protocol integers are ints). Used by every signer and verifier.
"""
import json
from typing import Any


def _reject_floats(obj: Any) -> None:
    if isinstance(obj, float):
        raise TypeError("floats are not allowed in signed material")
    if isinstance(obj, dict):
        for value in obj.values():
            _reject_floats(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            _reject_floats(value)


def canonical(obj: Any) -> bytes:
    """Serialize to canonical bytes. Raises TypeError on floats."""
    _reject_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
