# Implementation Notes (Initial Scaffold)

## Scope covered

- Added a minimal JWT package scaffold under `python/src/jwt`.
- Implemented base64url and JSON helpers with consistent error handling.
- Added a basic error hierarchy for token, signature, and claim validation.
- Implemented HS256 signing/verification via HMAC SHA-256.
- Added HS384/HS512 HMAC signing/verification variants.
- Added `encode`, `decode`, and `verify` helpers plus basic claim validation for `exp`, `nbf`, and `iat`.
- Added unit tests for token encoding, decoding, verification, and claim validation.

## Design notes

- Public helpers live in `jwt/__init__.py` to keep the API surface small.
- Algorithm selection uses a registry so additional algorithms can be added without changing the public API.
- Validation options are grouped in a dataclass to keep verification configuration explicit and typed.

## Next steps

- Extend algorithm support (RSA, ECDSA).
- Add key parsing helpers for PEM/JWK inputs.
- Expand claim validation to handle `iss`, `aud`, `sub`, and `jti`.
- Build tests and compatibility vectors aligned with the TypeScript implementation.
