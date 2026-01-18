"""Claim validation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional

from .errors import InvalidClaimError, InvalidTokenError
from .utils import parse_timespan


@dataclass(frozen=True)
class ValidationOptions:
    leeway: int | str = 0
    now: Optional[int] = None
    typ: Optional[str] = None
    require_exp: bool = False
    require_nbf: bool = False
    require_iat: bool = False
    require_iss: bool = False
    require_sub: bool = False
    require_aud: bool = False
    require_jti: bool = False
    issuer: Optional[str | Iterable[str]] = None
    subject: Optional[str] = None
    audience: Optional[str | Iterable[str]] = None
    max_token_age: Optional[int | str] = None

    def current_time(self) -> int:
        if self.now is not None:
            return self.now
        return int(datetime.now(tz=timezone.utc).timestamp())


def _ensure_int(value: Any, claim: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidClaimError(f"Claim '{claim}' must be a number")
    return int(value)


def _ensure_str(value: Any, claim: str) -> str:
    if not isinstance(value, str):
        raise InvalidClaimError(f"Claim '{claim}' must be a string")
    return value


def _normalize_expected(expected: str | Iterable[str], claim: str) -> list[str]:
    if isinstance(expected, str):
        return [expected]
    if isinstance(expected, Iterable):
        values = list(expected)
        if not values:
            raise InvalidClaimError(f"Claim '{claim}' expected values must not be empty")
        for item in values:
            if not isinstance(item, str):
                raise InvalidClaimError(f"Claim '{claim}' expected values must be strings")
        return values
    raise InvalidClaimError(f"Claim '{claim}' expected values must be a string or list")


def _normalize_audience(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        if not value:
            raise InvalidClaimError("Claim 'aud' must not be an empty list")
        for item in value:
            if not isinstance(item, str):
                raise InvalidClaimError("Claim 'aud' must contain only strings")
        return value
    raise InvalidClaimError("Claim 'aud' must be a string or list of strings")


def _normalize_typ(value: str) -> str:
    if "/" in value:
        return value.lower()
    return f"application/{value.lower()}"


def _normalize_max_token_age(value: int | str) -> int:
    if isinstance(value, bool):
        raise InvalidClaimError("Max token age must be a number or string")
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return parse_timespan(value)
        except InvalidTokenError as exc:
            raise InvalidClaimError("Max token age must be a valid time span string") from exc
    raise InvalidClaimError("Max token age must be a number or string")


def _normalize_leeway(value: int | str) -> int:
    if isinstance(value, bool):
        raise InvalidClaimError("Clock tolerance must be a number or string")
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return parse_timespan(value)
        except InvalidTokenError as exc:
            raise InvalidClaimError("Clock tolerance must be a valid time span string") from exc
    raise InvalidClaimError("Clock tolerance must be a number or string")


def validate_standard_claims(
    payload: Mapping[str, Any],
    options: ValidationOptions,
    header: Optional[Mapping[str, Any]] = None,
) -> None:
    now = options.current_time()
    leeway = _normalize_leeway(options.leeway)

    if options.typ is not None:
        header_value = None if header is None else header.get("typ")
        if not isinstance(header_value, str) or _normalize_typ(header_value) != _normalize_typ(options.typ):
            raise InvalidClaimError("Header 'typ' does not match expected value")

    if options.require_exp and "exp" not in payload:
        raise InvalidClaimError("Claim 'exp' is required")
    if options.require_nbf and "nbf" not in payload:
        raise InvalidClaimError("Claim 'nbf' is required")
    if options.require_iat and "iat" not in payload:
        raise InvalidClaimError("Claim 'iat' is required")
    if options.max_token_age is not None and "iat" not in payload:
        raise InvalidClaimError("Claim 'iat' is required")
    if options.require_iss and "iss" not in payload:
        raise InvalidClaimError("Claim 'iss' is required")
    if options.require_sub and "sub" not in payload:
        raise InvalidClaimError("Claim 'sub' is required")
    if options.require_aud and "aud" not in payload:
        raise InvalidClaimError("Claim 'aud' is required")
    if options.require_jti and "jti" not in payload:
        raise InvalidClaimError("Claim 'jti' is required")

    if options.issuer is not None:
        if "iss" not in payload:
            raise InvalidClaimError("Claim 'iss' is required")
        issuer = _ensure_str(payload["iss"], "iss")
        expected_issuers = _normalize_expected(options.issuer, "iss")
        if issuer not in expected_issuers:
            raise InvalidClaimError("Claim 'iss' does not match expected value")
    elif "iss" in payload:
        _ensure_str(payload["iss"], "iss")

    if options.subject is not None:
        if "sub" not in payload:
            raise InvalidClaimError("Claim 'sub' is required")
        subject = _ensure_str(payload["sub"], "sub")
        if subject != options.subject:
            raise InvalidClaimError("Claim 'sub' does not match expected value")
    elif "sub" in payload:
        _ensure_str(payload["sub"], "sub")

    if "aud" in payload:
        aud_list = _normalize_audience(payload["aud"])
        if options.audience is not None:
            expected_audience = set(_normalize_expected(options.audience, "aud"))
            if not expected_audience.intersection(aud_list):
                raise InvalidClaimError("Claim 'aud' does not match expected value")
    elif options.audience is not None:
        raise InvalidClaimError("Claim 'aud' is required")

    if "jti" in payload:
        _ensure_str(payload["jti"], "jti")

    if "exp" in payload:
        exp = _ensure_int(payload["exp"], "exp")
        if now >= exp + leeway:
            raise InvalidClaimError("Token has expired")

    if "nbf" in payload:
        nbf = _ensure_int(payload["nbf"], "nbf")
        if now < nbf - leeway:
            raise InvalidClaimError("Token is not yet valid")

    if "iat" in payload:
        iat = _ensure_int(payload["iat"], "iat")
        if options.max_token_age is not None:
            max_age = _normalize_max_token_age(options.max_token_age)
            age = now - iat
            if age - leeway > max_age:
                raise InvalidClaimError("Token is too old")
            if age < -leeway:
                raise InvalidClaimError("Token was issued in the future")
