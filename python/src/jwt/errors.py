"""JWT error types."""


class JWTError(Exception):
    """Base class for JWT errors."""


class InvalidTokenError(JWTError):
    """Raised when a token is malformed or otherwise invalid."""


class InvalidSignatureError(JWTError):
    """Raised when a token signature does not match."""


class InvalidClaimError(JWTError):
    """Raised when a claim fails validation."""


class UnsupportedAlgorithmError(JWTError):
    """Raised when the requested algorithm is not supported."""
