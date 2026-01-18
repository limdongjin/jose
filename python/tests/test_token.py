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

    def test_encode_decode_roundtrip_for_hs384_hs512(self) -> None:
        payload = {"sub": "user-123", "exp": 1_800_000_000}
        for alg in ("HS384", "HS512"):
            token = encode(payload, "secret", alg)

            result = decode(token)
            self.assertEqual(result.header["alg"], alg)
            self.assertEqual(result.payload["sub"], "user-123")

            verified = verify(token, "secret", algorithms=[alg], options=ValidationOptions(now=1_700_000_000))
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

    def test_encode_verify_with_oct_jwk(self) -> None:
        payload = {"sub": "user-123", "exp": 1_800_000_000}
        jwk = {"kty": "oct", "k": "c2VjcmV0"}

        token = encode(payload, jwk, "HS256")
        verified = verify(token, jwk, algorithms=["HS256"], options=ValidationOptions(now=1_700_000_000))
        self.assertEqual(verified["sub"], "user-123")

    def test_verify_rejects_expired_token(self) -> None:
        payload = {"sub": "user-123", "exp": 1_700_000_000}
        token = encode(payload, "secret", "HS256")
        with self.assertRaises(InvalidClaimError):
            verify(token, "secret", algorithms=["HS256"], options=ValidationOptions(now=1_700_000_100))

    def test_verify_rejects_exp_equal_now(self) -> None:
        payload = {"sub": "user-123", "exp": 1_700_000_000}
        token = encode(payload, "secret", "HS256")
        with self.assertRaises(InvalidClaimError):
            verify(token, "secret", algorithms=["HS256"], options=ValidationOptions(now=1_700_000_000))

    def test_verify_accepts_timespan_leeway(self) -> None:
        payload = {"sub": "user-123", "exp": 1_700_000_000}
        token = encode(payload, "secret", "HS256")
        verified = verify(
            token,
            "secret",
            algorithms=["HS256"],
            options=ValidationOptions(now=1_700_000_005, leeway="10 seconds"),
        )
        self.assertEqual(verified["sub"], "user-123")

    def test_verify_rejects_invalid_leeway_timespan(self) -> None:
        payload = {"sub": "user-123", "exp": 1_700_000_000}
        token = encode(payload, "secret", "HS256")
        with self.assertRaises(InvalidClaimError):
            verify(
                token,
                "secret",
                algorithms=["HS256"],
                options=ValidationOptions(now=1_700_000_005, leeway="soon"),
            )

    def test_verify_validates_issuer_subject_audience(self) -> None:
        payload = {"iss": "issuer-a", "sub": "user-123", "aud": ["service-a", "service-b"]}
        token = encode(payload, "secret", "HS256")

        verified = verify(
            token,
            "secret",
            algorithms=["HS256"],
            options=ValidationOptions(issuer="issuer-a", subject="user-123", audience="service-b"),
        )
        self.assertEqual(verified["iss"], "issuer-a")

    def test_verify_rejects_mismatched_issuer(self) -> None:
        payload = {"iss": "issuer-a", "sub": "user-123"}
        token = encode(payload, "secret", "HS256")
        with self.assertRaises(InvalidClaimError):
            verify(token, "secret", algorithms=["HS256"], options=ValidationOptions(issuer="issuer-b"))

    def test_verify_rejects_mismatched_audience(self) -> None:
        payload = {"aud": "service-a"}
        token = encode(payload, "secret", "HS256")
        with self.assertRaises(InvalidClaimError):
            verify(token, "secret", algorithms=["HS256"], options=ValidationOptions(audience="service-b"))

    def test_verify_requires_jti(self) -> None:
        payload = {"sub": "user-123"}
        token = encode(payload, "secret", "HS256")
        with self.assertRaises(InvalidClaimError):
            verify(token, "secret", algorithms=["HS256"], options=ValidationOptions(require_jti=True))

    def test_verify_checks_typ_header(self) -> None:
        payload = {"sub": "user-123"}
        token = encode(payload, "secret", "HS256")
        verified = verify(token, "secret", algorithms=["HS256"], options=ValidationOptions(typ="JWT"))
        self.assertEqual(verified["sub"], "user-123")

        with self.assertRaises(InvalidClaimError):
            verify(token, "secret", algorithms=["HS256"], options=ValidationOptions(typ="at+jwt"))

    def test_verify_enforces_max_token_age(self) -> None:
        payload = {"sub": "user-123", "iat": 1_700_000_000}
        token = encode(payload, "secret", "HS256")

        verified = verify(
            token,
            "secret",
            algorithms=["HS256"],
            options=ValidationOptions(now=1_700_000_100, max_token_age="2 minutes"),
        )
        self.assertEqual(verified["sub"], "user-123")

        with self.assertRaises(InvalidClaimError):
            verify(
                token,
                "secret",
                algorithms=["HS256"],
                options=ValidationOptions(now=1_700_000_100, max_token_age=50),
            )

    def test_verify_requires_iat_for_max_token_age(self) -> None:
        payload = {"sub": "user-123"}
        token = encode(payload, "secret", "HS256")
        with self.assertRaises(InvalidClaimError):
            verify(
                token,
                "secret",
                algorithms=["HS256"],
                options=ValidationOptions(now=1_700_000_100, max_token_age=60),
            )

    def test_verify_allows_future_iat_without_max_token_age(self) -> None:
        payload = {"sub": "user-123", "iat": 1_700_000_500}
        token = encode(payload, "secret", "HS256")

        verified = verify(token, "secret", algorithms=["HS256"], options=ValidationOptions(now=1_700_000_100))
        self.assertEqual(verified["sub"], "user-123")

    def test_decode_requires_three_parts(self) -> None:
        with self.assertRaises(InvalidTokenError):
            decode("not-a-jwt")

    def test_verify_rejects_unencoded_payload_header(self) -> None:
        payload = {"sub": "user-123"}
        token = encode(payload, "secret", "HS256", headers={"b64": False, "crit": ["b64"]})
        with self.assertRaises(InvalidTokenError):
            verify(token, "secret", algorithms=["HS256"])

    def test_verify_rejects_invalid_crit_header(self) -> None:
        payload = {"sub": "user-123"}

        token = encode(payload, "secret", "HS256", headers={"crit": "b64"})
        with self.assertRaises(InvalidTokenError):
            verify(token, "secret", algorithms=["HS256"])

        token = encode(payload, "secret", "HS256", headers={"crit": []})
        with self.assertRaises(InvalidTokenError):
            verify(token, "secret", algorithms=["HS256"])

    def test_verify_rejects_unrecognized_crit_parameter(self) -> None:
        payload = {"sub": "user-123"}
        token = encode(payload, "secret", "HS256", headers={"crit": ["exp"]})
        with self.assertRaises(InvalidTokenError):
            verify(token, "secret", algorithms=["HS256"])

    def test_verify_rejects_missing_crit_parameter(self) -> None:
        payload = {"sub": "user-123"}
        token = encode(payload, "secret", "HS256", headers={"crit": ["b64"]})
        with self.assertRaises(InvalidTokenError):
            verify(token, "secret", algorithms=["HS256"])

    def test_verify_rejects_non_boolean_b64(self) -> None:
        payload = {"sub": "user-123"}
        token = encode(payload, "secret", "HS256", headers={"crit": ["b64"], "b64": "false"})
        with self.assertRaises(InvalidTokenError):
            verify(token, "secret", algorithms=["HS256"])


if __name__ == "__main__":
    unittest.main()
