"""Password and API-key hashing.

Uses ``hashlib.scrypt`` from the standard library: no native extension to
install, and a memory-hard KDF for user passwords. API-key secrets are
high-entropy random strings, so the same KDF with lighter parameters is used
to keep verification cheap on the hot path.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets as _secrets

_PASSWORD_PARAMS = {"n": 2**14, "r": 8, "p": 1}
_TOKEN_PARAMS = {"n": 2**12, "r": 8, "p": 1}
_SALT_BYTES = 16
_KEY_LEN = 32


def _hash(value: str, salt: bytes, params: dict[str, int]) -> bytes:
    return hashlib.scrypt(value.encode("utf-8"), salt=salt, dklen=_KEY_LEN, **params)


def _encode(kind: str, salt: bytes, digest: bytes) -> str:
    return f"scrypt${kind}${salt.hex()}${digest.hex()}"


def _params_for(kind: str) -> dict[str, int]:
    return _PASSWORD_PARAMS if kind == "pw" else _TOKEN_PARAMS


def hash_password(password: str) -> str:
    salt = _secrets.token_bytes(_SALT_BYTES)
    return _encode("pw", salt, _hash(password, salt, _PASSWORD_PARAMS))


def hash_secret(secret: str) -> str:
    salt = _secrets.token_bytes(_SALT_BYTES)
    return _encode("tk", salt, _hash(secret, salt, _TOKEN_PARAMS))


def verify(value: str, encoded: str | None) -> bool:
    """Constant-time verification of a password or secret against its hash."""
    if not encoded:
        return False
    try:
        scheme, kind, salt_hex, digest_hex = encoded.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    candidate = _hash(value, salt, _params_for(kind))
    return hmac.compare_digest(candidate, expected)


def random_token(nbytes: int = 32) -> str:
    return _secrets.token_urlsafe(nbytes)


def random_id(nbytes: int = 8) -> str:
    return _secrets.token_hex(nbytes)
