# Implementation Notes (Initial Scaffold)

## Scope covered

- Added a minimal JWT package scaffold under `python/src/jwt`.
- Implemented base64url and JSON helpers with consistent error handling.
- Added a basic error hierarchy for token, signature, and claim validation.
- Implemented HS256 signing/verification via HMAC SHA-256.
- Added HS384/HS512 HMAC signing/verification variants.
- Added `encode`, `decode`, and `verify` helpers plus basic claim validation for `exp`, `nbf`, and `iat`.
- Added issuer (`iss`), subject (`sub`), audience (`aud`), and JWT ID (`jti`) validation with optional requirements.
- Added unit tests for token encoding, decoding, verification, and claim validation.
- Added `kty: "oct"` JWK handling for HMAC keys to align with TypeScript import behavior.
- Added `typ` header validation with media type normalization to align with TypeScript JWT verification.
- Added `max_token_age` validation and human-readable time span parsing for `iat` claim enforcement.
- Added human-readable time span parsing for `leeway` (clock tolerance) when validating time-based claims.
- Added a JWT verification guard that rejects `crit: ["b64"]` with `b64: false` unencoded payload requests.
- Added `crit` header validation for JWTs to enforce recognized parameters and `b64` boolean handling.

## Design notes

- Public helpers live in `jwt/__init__.py` to keep the API surface small.
- Algorithm selection uses a registry so additional algorithms can be added without changing the public API.
- Validation options are grouped in a dataclass to keep verification configuration explicit and typed.
- Claim validation keeps string-only enforcement for identity claims to match TypeScript behavior.

## Next steps

- Extend algorithm support (RSA, ECDSA).
- Add key parsing helpers for PEM and asymmetric JWK inputs.
- Build tests and compatibility vectors aligned with the TypeScript implementation.

## TypeScript parity references

- Symmetric JWK import behavior follows the TypeScript `importJWK` `oct` branch:

  ```ts
  case 'oct':
    if (typeof jwk.k !== 'string' || !jwk.k) {
      throw new TypeError('missing "k" (Key Value) Parameter value')
    }

    return decodeBase64URL(jwk.k)
  ```

  (Source: `src/key/import.ts`)

- `typ` header matching follows the TypeScript `normalizeTyp` helper:

  ```ts
  const normalizeTyp = (value: string) => {
    if (value.includes('/')) {
      return value.toLowerCase()
    }

    return `application/${value.toLowerCase()}`
  }
  ```

  (Source: `src/lib/jwt_claims_set.ts`)

- Unencoded payloads are rejected to match the TypeScript JWT verifier:

  ```ts
  if (verified.protectedHeader.crit?.includes('b64') && verified.protectedHeader.b64 === false) {
    throw new JWTInvalid('JWTs MUST NOT use unencoded payload')
  }
  ```

  (Source: `src/jwt/verify.ts`)

- Critical header validation mirrors the TypeScript `validateCrit` helper and JWS `b64` type checks:

  ```ts
  if (
    !Array.isArray(protectedHeader.crit) ||
    protectedHeader.crit.length === 0 ||
    protectedHeader.crit.some((input: string) => typeof input !== 'string' || input.length === 0)
  ) {
    throw new Err(
      '"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present',
    )
  }

  for (const parameter of protectedHeader.crit) {
    if (!recognized.has(parameter)) {
      throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`)
    }

    if (joseHeader[parameter] === undefined) {
      throw new Err(`Extension Header Parameter "${parameter}" is missing`)
    }
  }
  ```

  (Source: `src/lib/validate_crit.ts`)

  ```ts
  if (extensions.has('b64')) {
    b64 = parsedProt.b64!
    if (typeof b64 !== 'boolean') {
      throw new JWSInvalid(
        'The "b64" (base64url-encode payload) Header Parameter must be a boolean',
      )
    }
  }
  ```

  (Source: `src/jws/flattened/verify.ts`)

- Clock tolerance parsing mirrors the TypeScript `clockTolerance` handling:

  ```ts
  let tolerance: number
  switch (typeof options.clockTolerance) {
    case 'string':
      tolerance = secs(options.clockTolerance)
      break
    case 'number':
      tolerance = options.clockTolerance
      break
    case 'undefined':
      tolerance = 0
      break
    default:
      throw new TypeError('Invalid clockTolerance option type')
  }
  ```

  (Source: `src/lib/jwt_claims_set.ts`)
