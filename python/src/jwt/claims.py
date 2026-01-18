"""Claim validation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from .errors import InvalidClaimError


@dataclass(frozen=True)
class ValidationOptions:
    leeway: int = 0
    now: Optional[int] = None
    require_exp: bool = False
    require_nbf: bool = False
    require_iat: bool = False

    def current_time(self) -> int:
        if self.now is not None:
            return self.now
        return int(datetime.now(tz=timezone.utc).timestamp())


def _ensure_int(value: Any, claim: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidClaimError(f"Claim '{claim}' must be a number")
    return int(value)


def validate_standard_claims(payload: Mapping[str, Any], options: ValidationOptions) -> None:
    now = options.current_time()
    leeway = options.leeway

    if options.require_exp and "exp" not in payload:
        raise InvalidClaimError("Claim 'exp' is required")
    if options.require_nbf and "nbf" not in payload:
        raise InvalidClaimError("Claim 'nbf' is required")
    if options.require_iat and "iat" not in payload:
        raise InvalidClaimError("Claim 'iat' is required")

    if "exp" in payload:
        exp = _ensure_int(payload["exp"], "exp")
        if now > exp + leeway:
            raise InvalidClaimError("Token has expired")

    if "nbf" in payload:
        nbf = _ensure_int(payload["nbf"], "nbf")
        if now < nbf - leeway:
            raise InvalidClaimError("Token is not yet valid")

    if "iat" in payload:
        iat = _ensure_int(payload["iat"], "iat")
        if now + leeway < iat:
            raise InvalidClaimError("Token was issued in the future")
