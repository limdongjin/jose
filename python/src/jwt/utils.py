"""Utility helpers for JWT encoding/decoding."""

from __future__ import annotations

import base64
import json
from typing import Any

from .errors import InvalidTokenError


def _strip_padding(value: str) -> str:
    return value.rstrip("=")


def b64url_encode(raw: bytes) -> str:
    """Encode bytes using base64url without padding."""
    return _strip_padding(base64.urlsafe_b64encode(raw).decode("ascii"))


def b64url_decode(encoded: str) -> bytes:
    """Decode a base64url string without padding."""
    if not isinstance(encoded, str):
        raise InvalidTokenError("Base64 input must be a string")
    padding = "=" * (-len(encoded) % 4)
    try:
        return base64.urlsafe_b64decode(encoded + padding)
    except (ValueError, TypeError) as exc:
        raise InvalidTokenError("Base64 input is not valid") from exc


def json_dumps(data: Any) -> str:
    """Serialize data to JSON using compact separators."""
    try:
        return json.dumps(data, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise InvalidTokenError("JSON serialization failed") from exc


def json_loads(raw: str) -> Any:
    """Parse JSON from a string."""
    try:
        return json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise InvalidTokenError("JSON parsing failed") from exc
