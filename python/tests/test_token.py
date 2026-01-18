import os
import sys
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from jwt import (
    ValidationOptions,
    decode,
    encode,
    verify,
    InvalidClaimError,
    InvalidSignatureError,
    InvalidTokenError,
)


class TokenTests(unittest.TestCase):
    def test_encode_decode_roundtrip(self) -> None:
        payload = {"sub": "user-123", "exp": 1_800_000_000}
        token = encode(payload, "secret", "HS256")

        result = decode(token)
        self.assertEqual(result.header["alg"], "HS256")
        self.assertEqual(result.payload["sub"], "user-123")

        verified = verify(token, "secret", algorithms=["HS256"], options=ValidationOptions(now=1_700_000_000))
        self.assertEqual(verified["sub"], "user-123")

    def test_verify_rejects_invalid_signature(self) -> None:
        payload = {"sub": "user-123", "exp": 1_800_000_000}
        token = encode(payload, "secret", "HS256")
        with self.assertRaises(InvalidSignatureError):
            verify(token, "wrong-secret", algorithms=["HS256"], options=ValidationOptions(now=1_700_000_000))

    def test_verify_rejects_disallowed_algorithm(self) -> None:
        payload = {"sub": "user-123", "exp": 1_800_000_000}
        token = encode(payload, "secret", "HS256")
        with self.assertRaises(InvalidSignatureError):
            verify(token, "secret", algorithms=["HS384"], options=ValidationOptions(now=1_700_000_000))

    def test_verify_rejects_expired_token(self) -> None:
        payload = {"sub": "user-123", "exp": 1_700_000_000}
        token = encode(payload, "secret", "HS256")
        with self.assertRaises(InvalidClaimError):
            verify(token, "secret", algorithms=["HS256"], options=ValidationOptions(now=1_700_000_100))

    def test_decode_requires_three_parts(self) -> None:
        with self.assertRaises(InvalidTokenError):
            decode("not-a-jwt")


if __name__ == "__main__":
    unittest.main()
