"""Algorithm registry and implementations."""

from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass
from typing import Dict, Protocol

from .errors import InvalidSignatureError, UnsupportedAlgorithmError


class Algorithm(Protocol):
    name: str

    def sign(self, key: bytes, signing_input: bytes) -> bytes:
        """Return a signature for the given input."""

    def verify(self, key: bytes, signing_input: bytes, signature: bytes) -> None:
        """Validate the signature for the given input."""


@dataclass(frozen=True)
class HMACAlgorithm:
    name: str
    digestmod: str

    def sign(self, key: bytes, signing_input: bytes) -> bytes:
        return hmac.new(key, signing_input, getattr(hashlib, self.digestmod)).digest()

    def verify(self, key: bytes, signing_input: bytes, signature: bytes) -> None:
        expected = self.sign(key, signing_input)
        if not hmac.compare_digest(expected, signature):
            raise InvalidSignatureError("Signature verification failed")


_ALGORITHMS: Dict[str, Algorithm] = {
    "HS256": HMACAlgorithm(name="HS256", digestmod="sha256"),
}


def get_algorithm(name: str) -> Algorithm:
    try:
        return _ALGORITHMS[name]
    except KeyError as exc:
        raise UnsupportedAlgorithmError(f"Algorithm '{name}' is not supported") from exc


def list_algorithms() -> Dict[str, Algorithm]:
    return dict(_ALGORITHMS)
