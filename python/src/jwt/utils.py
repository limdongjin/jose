"""Utility helpers for JWT encoding/decoding."""

from __future__ import annotations

import base64
import json
import math
import re
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


_TIME_SPAN_RE = re.compile(
    r"^(\+|\-)? ?(\d+|\d+\.\d+) ?"
    r"(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)"
    r"(?: (ago|from now))?$",
    re.IGNORECASE,
)

_SECONDS_BY_UNIT = {
    "sec": 1,
    "secs": 1,
    "second": 1,
    "seconds": 1,
    "s": 1,
    "minute": 60,
    "minutes": 60,
    "min": 60,
    "mins": 60,
    "m": 60,
    "hour": 60 * 60,
    "hours": 60 * 60,
    "hr": 60 * 60,
    "hrs": 60 * 60,
    "h": 60 * 60,
    "day": 60 * 60 * 24,
    "days": 60 * 60 * 24,
    "d": 60 * 60 * 24,
    "week": 60 * 60 * 24 * 7,
    "weeks": 60 * 60 * 24 * 7,
    "w": 60 * 60 * 24 * 7,
    "year": int(60 * 60 * 24 * 365.25),
    "years": int(60 * 60 * 24 * 365.25),
    "yr": int(60 * 60 * 24 * 365.25),
    "yrs": int(60 * 60 * 24 * 365.25),
    "y": int(60 * 60 * 24 * 365.25),
}


def _round_half_up(value: float) -> int:
    return int(math.floor(value + 0.5))


def parse_timespan(value: str) -> int:
    """Parse a human readable time span into seconds."""
    if not isinstance(value, str):
        raise InvalidTokenError("Time span must be a string")

    match = _TIME_SPAN_RE.match(value)
    if not match or (match.group(4) and match.group(1)):
        raise InvalidTokenError("Invalid time span format")

    amount = float(match.group(2))
    unit = match.group(3).lower()
    seconds = _round_half_up(amount * _SECONDS_BY_UNIT[unit])

    if match.group(1) == "-" or match.group(4) == "ago":
        return -seconds
    return seconds
