# Release Notes

## [Unreleased]

### Added
- Added issuer (`iss`), subject (`sub`), audience (`aud`), and JWT ID (`jti`) claim validation options.
- Added audience list matching and string-type enforcement for standard identity claims.
- Added support for octet (`kty: "oct"`) JWK inputs when signing or verifying HMAC tokens.
- Added `typ` header validation support with TypeScript-compatible media type normalization.
- Added `max_token_age` validation with human-readable time span parsing to align with TypeScript `maxTokenAge` behavior.
- Added rejection of JWTs that request unencoded payloads via `crit: ["b64"]` and `b64: false`.
- Added `crit` header validation for JWTs, enforcing recognized parameters and required protected values.

### Updated
- Added verification coverage for issuer/subject/audience matching and `jti` requirements.
- Aligned `exp` boundary handling and `iat` future checks with the TypeScript `validateClaimsSet` behavior.

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

- `exp` and `iat` timestamp comparisons align with the TypeScript claim validation rules:

  ```ts
  if (payload.exp !== undefined) {
    if (payload.exp <= now - tolerance) {
      throw new JWTExpired('"exp" claim timestamp check failed', payload, 'exp', 'check_failed')
    }
  }

  if (maxTokenAge) {
    if (age < 0 - tolerance) {
      throw new JWTClaimValidationFailed(
        '"iat" claim timestamp check failed (it should be in the past)',
        payload,
        'iat',
        'check_failed',
      )
    }
  }
  ```

  (Source: `src/lib/jwt_claims_set.ts`)

- JWTs reject the JWS unencoded payload extension when `crit` includes `b64` and `b64` is `false`:

  ```ts
  if (verified.protectedHeader.crit?.includes('b64') && verified.protectedHeader.b64 === false) {
    throw new JWTInvalid('JWTs MUST NOT use unencoded payload')
  }
  ```

  (Source: `src/jwt/verify.ts`)

- Critical header validation and `b64` type checks follow the TypeScript `validateCrit` helper and JWS verification logic:

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
