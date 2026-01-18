"""JWT encode/decode/verify helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from .algorithms import get_algorithm
from .claims import ValidationOptions, validate_standard_claims
from .errors import InvalidSignatureError, InvalidTokenError
from .keys import KeyLike, ensure_bytes
from .utils import b64url_decode, b64url_encode, json_dumps, json_loads


@dataclass(frozen=True)
class DecodeResult:
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: bytes
    signing_input: bytes


def _split_token(token: str) -> Tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidTokenError("Token must have exactly three parts")
    return parts[0], parts[1], parts[2]


def decode(token: str) -> DecodeResult:
    if not isinstance(token, str):
        raise InvalidTokenError("Token must be a string")
    encoded_header, encoded_payload, encoded_signature = _split_token(token)

    header = json_loads(b64url_decode(encoded_header).decode("utf-8"))
    payload = json_loads(b64url_decode(encoded_payload).decode("utf-8"))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise InvalidTokenError("Token header and payload must be JSON objects")

    signature = b64url_decode(encoded_signature)
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    return DecodeResult(header=header, payload=payload, signature=signature, signing_input=signing_input)


def encode(
    payload: Mapping[str, Any],
    key: KeyLike,
    alg: str,
    headers: Optional[Mapping[str, Any]] = None,
) -> str:
    if not isinstance(payload, Mapping):
        raise InvalidTokenError("Payload must be a mapping")

    header_data: Dict[str, Any] = {"typ": "JWT", "alg": alg}
    if headers:
        header_data.update(headers)

    encoded_header = b64url_encode(json_dumps(header_data).encode("utf-8"))
    encoded_payload = b64url_encode(json_dumps(dict(payload)).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")

    algorithm = get_algorithm(alg)
    signature = algorithm.sign(ensure_bytes(key), signing_input)
    encoded_signature = b64url_encode(signature)

    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def verify(
    token: str,
    key: KeyLike,
    algorithms: Optional[Iterable[str]] = None,
    options: Optional[ValidationOptions] = None,
) -> Dict[str, Any]:
    result = decode(token)
    alg = result.header.get("alg")
    if not isinstance(alg, str):
        raise InvalidTokenError("Header 'alg' must be a string")

    if algorithms is not None and alg not in set(algorithms):
        raise InvalidSignatureError("Token algorithm is not allowed")

    algorithm = get_algorithm(alg)
    algorithm.verify(ensure_bytes(key), result.signing_input, result.signature)

    validation_options = options or ValidationOptions()
    validate_standard_claims(result.payload, validation_options, header=result.header)

    return result.payload
