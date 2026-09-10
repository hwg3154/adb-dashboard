"""Password hashing and password policy.

v1 has one account, created by the first-run wizard. Argon2id is the preferred scheme
(`argon2-cffi`); when that wheel is unavailable the code falls back to `hashlib.scrypt`. Both
schemes are salted, memory-hard and verified in constant time.

Never log a password, and never echo one back to the browser.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets

from .config import Config

try:  # pragma: no cover - optional dependency
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerifyMismatchError
except ImportError:  # pragma: no cover
    PasswordHasher = None  # type: ignore[assignment]
    InvalidHashError = None  # type: ignore[assignment, misc]
    VerifyMismatchError = None  # type: ignore[assignment, misc]

DEFAULT_USERNAME = "operator"

USERNAME_MIN_CHARS = 3
USERNAME_MAX_CHARS = 32
USERNAME_MAX_BYTES = 64
PASSWORD_MIN_CHARS = 10
PASSWORD_MAX_CHARS = 128
PASSWORD_MAX_BYTES = 512
MAX_USERNAME_BYTES = 64
LOGIN_ERROR_MESSAGE = "Sign-in failed"

USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{1,30}$")

_ARGON2_PREFIX = "$argon2id$"
_SCRYPT_PREFIX = "scrypt"
#: Stored form is `$scrypt$n=..,r=..,p=..$salt$digest`, so it splits into five fields.
_SCRYPT_MARKER = "$scrypt$"
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 64 * 1024 * 1024
_SALT_BYTES = 16
_TOKEN_BYTES = 32
_HASH_FIELD_BYTES = 256
_HEX_DIGITS = "0123456789abcdef"

_ZERO_HASH = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$" + "A" * 43


def hash_password(password: str) -> str:
    """Hash a password with Argon2id, falling back to scrypt."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")

    if PasswordHasher is not None:
        try:
            return PasswordHasher().hash(password)
        except Exception:
            pass

    salt = secrets.token_bytes(_SALT_BYTES)
    try:
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
            dklen=_SCRYPT_DKLEN,
            maxmem=_SCRYPT_MAXMEM,
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeError("password hashing is unavailable") from exc

    return "$".join(
        (
            "",
            _SCRYPT_PREFIX,
            f"n={_SCRYPT_N},r={_SCRYPT_R},p={_SCRYPT_P}",
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )
    )


def verify_password(encoded: object, password: str) -> bool:
    """Verify a password against a stored hash. Never raises on bad input."""
    if not isinstance(password, str) or not password or len(password) > PASSWORD_MAX_BYTES:
        return False
    if not isinstance(encoded, str) or not encoded:
        return False

    if encoded.startswith(_ARGON2_PREFIX):
        if PasswordHasher is None or InvalidHashError is None:
            return False
        try:
            return bool(PasswordHasher().verify(encoded, password))
        except (VerifyMismatchError, InvalidHashError):
            return False
        except Exception:
            return False

    if not encoded.startswith(_SCRYPT_MARKER):
        return False

    parts = encoded.split("$")
    if len(parts) != 5 or parts[1] != _SCRYPT_PREFIX:
        return False
    params = _parse_params(parts[2])
    if params is None:
        return False

    try:
        salt = base64.b64decode(parts[3], validate=True)
        expected = base64.b64decode(parts[4], validate=True)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=params[0],
            r=params[1],
            p=params[2],
            dklen=len(expected),
            maxmem=_SCRYPT_MAXMEM,
        )
    except (TypeError, ValueError):
        return False
    if not expected:
        return False
    return hmac.compare_digest(bytes(actual), bytes(expected))


def check_password_strength(password: object) -> list[str]:
    """Return the rules a password breaks. An empty list means it is acceptable."""
    if not isinstance(password, str) or not password:
        return ["password is required"]
    if len(password.encode("utf-8")) > PASSWORD_MAX_BYTES:
        return ["password is too long"]

    issues: list[str] = []
    if len(password) < PASSWORD_MIN_CHARS:
        issues.append(f"password must be at least {PASSWORD_MIN_CHARS} characters")
    if len(password) > PASSWORD_MAX_CHARS:
        issues.append("password is too long")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in password):
        issues.append("password contains control characters")
    if password != password.strip() or not password.strip():
        issues.append("password has leading or trailing spaces")
    if len(set(password)) < 4:
        issues.append("password is too simple")
    return issues


def check_username(value: object) -> str:
    """Normalize a username; anything unusual falls back to the built-in account name."""
    if value is None:
        return DEFAULT_USERNAME
    if not isinstance(value, str):
        return DEFAULT_USERNAME
    candidate = value.strip().lower()
    if not candidate:
        return DEFAULT_USERNAME
    if len(candidate) > MAX_USERNAME_BYTES:
        raise ValueError("username is too long")
    if len(candidate) < USERNAME_MIN_CHARS:
        raise ValueError("username is too short")
    if not USERNAME_PATTERN.match(candidate):
        raise ValueError("username is not valid")
    return candidate


def issue_token() -> str:
    """Create a session or CSRF token: 256 random bits, hex encoded."""
    return secrets.token_hex(_TOKEN_BYTES)


def is_token(value: object) -> bool:
    """A token is exactly one hex string of the negotiated length, nothing else."""
    return isinstance(value, str) and len(value) == _TOKEN_BYTES * 2 and all(c in _HEX_DIGITS for c in value)


def clean_token(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def clean_ip(value: object) -> str:
    import ipaddress

    if not isinstance(value, str):
        return ""
    raw = value.strip()
    if not raw or len(raw) > 45:
        return ""
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse_params(raw: str) -> tuple[int, int, int] | None:
    values: dict[str, int] = {}
    for chunk in raw.split(","):
        key, sep, value = chunk.partition("=")
        if not sep:
            return None
        key = key.strip()
        if key not in ("n", "r", "p") or not value.strip().isdigit():
            return None
        values[key] = int(value)
    if len(values) != 3:
        return None
    return values["n"], values["r"], values["p"]


def policy_limits(config: Config) -> tuple[int, int]:
    return config.password_min_chars, config.password_max_chars
