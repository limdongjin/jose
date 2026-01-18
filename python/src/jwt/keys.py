"""Key helpers."""

from __future__ import annotations

from typing import Any, Mapping, Union

from .errors import InvalidTokenError
from .utils import b64url_decode


KeyLike = Union[str, bytes, Mapping[str, Any]]


def ensure_bytes(key: KeyLike) -> bytes:
    if isinstance(key, bytes):
        return key
    if isinstance(key, str):
        return key.encode("utf-8")
    if isinstance(key, Mapping):
        kty = key.get("kty")
        if kty != "oct":
            raise InvalidTokenError("Only 'oct' JWK keys are supported")
        k = key.get("k")
        if not isinstance(k, str) or not k:
            raise InvalidTokenError("JWK 'k' must be a non-empty string")
        return b64url_decode(k)
    raise InvalidTokenError("Key must be bytes, string, or JWK mapping")
