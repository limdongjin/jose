"""Key helpers."""

from __future__ import annotations

from typing import Union

from .errors import InvalidTokenError


KeyLike = Union[str, bytes]


def ensure_bytes(key: KeyLike) -> bytes:
    if isinstance(key, bytes):
        return key
    if isinstance(key, str):
        return key.encode("utf-8")
    raise InvalidTokenError("Key must be bytes or string")
