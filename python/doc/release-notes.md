# Release Notes

## [Unreleased]

### Added
- Added HS384 and HS512 HMAC variants to the Python JWT algorithm registry.
- Added round-trip encode/decode/verify coverage for HS384 and HS512.

### References (TypeScript parity)
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
