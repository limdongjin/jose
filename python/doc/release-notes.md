# Release Notes

## [Unreleased]

### Added
- Added issuer (`iss`), subject (`sub`), audience (`aud`), and JWT ID (`jti`) claim validation options.
- Added audience list matching and string-type enforcement for standard identity claims.

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
