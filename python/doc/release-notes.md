# Release Notes

## [Unreleased]

### Added
- Added issuer (`iss`), subject (`sub`), audience (`aud`), and JWT ID (`jti`) claim validation options.
- Added audience list matching and string-type enforcement for standard identity claims.
- Added support for octet (`kty: "oct"`) JWK inputs when signing or verifying HMAC tokens.
- Added `typ` header validation support with TypeScript-compatible media type normalization.
- Added `max_token_age` validation with human-readable time span parsing to align with TypeScript `maxTokenAge` behavior.

### Updated
- Added verification coverage for issuer/subject/audience matching and `jti` requirements.

### References (TypeScript parity)
- Claim presence and issuer/subject/audience matching mirror the TypeScript validation flow:

  ```ts
  if (issuer && !((Array.isArray(issuer) ? issuer : [issuer]) as unknown[]).includes(payload.iss!)) {
    throw new JWTClaimValidationFailed(
      'unexpected "iss" claim value',
      payload,
      'iss',
      'check_failed',
    )
  }

  if (
    audience &&
    !checkAudiencePresence(payload.aud, typeof audience === 'string' ? [audience] : audience)
  ) {
    throw new JWTClaimValidationFailed(
      'unexpected "aud" claim value',
      payload,
      'aud',
      'check_failed',
    )
  }
  ```

  (Source: `src/lib/jwt_claims_set.ts`)

- `typ` header normalization and matching follow the TypeScript helper:

  ```ts
  const normalizeTyp = (value: string) => {
    if (value.includes('/')) {
      return value.toLowerCase()
    }

    return `application/${value.toLowerCase()}`
  }
  ```

  (Source: `src/lib/jwt_claims_set.ts`)

- `maxTokenAge` parsing and enforcement mirror the TypeScript `secs` helper and age checks:

  ```ts
  const max = typeof maxTokenAge === 'number' ? maxTokenAge : secs(maxTokenAge)

  if (age - tolerance > max) {
    throw new JWTExpired(
      '"iat" claim timestamp check failed (too far in the past)',
      payload,
      'iat',
      'check_failed',
    )
  }
  ```

  (Source: `src/lib/jwt_claims_set.ts`)

- Human-readable time spans follow the same regex and unit mapping as the TypeScript helper:

  ```ts
  const REGEX =
    /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i
  ```

  (Source: `src/lib/jwt_claims_set.ts`)

- JWK `oct` key handling mirrors the TypeScript `importJWK` branch for symmetric keys:

  ```ts
  case 'oct':
    if (typeof jwk.k !== 'string' || !jwk.k) {
      throw new TypeError('missing "k" (Key Value) Parameter value')
    }

    return decodeBase64URL(jwk.k)
  ```

  (Source: `src/key/import.ts`)

### Previously Added
- Added HS384 and HS512 HMAC variants to the Python JWT algorithm registry.
- Added round-trip encode/decode/verify coverage for HS384 and HS512.

### Previous References (TypeScript parity)
- The HS* mapping mirrors the TypeScript implementation that derives the HMAC hash
  from the `alg` suffix when importing a raw key:

  ```ts
  return crypto.subtle.importKey(
    'raw',
    key as Uint8Array<ArrayBuffer>,
    { hash: `SHA-${alg.slice(-3)}`, name: 'HMAC' },
    false,
    [usage],
  )
  ```

  (Source: `src/lib/get_sign_verify_key.ts`)
