"""Password hashing helpers for awesome-python-auth.

Uses the ``bcrypt`` library directly to avoid compatibility issues with
``passlib`` and ``bcrypt >= 4.x``.
"""

import bcrypt


def hash_password(password: str) -> str:
    """Return a bcrypt hash of *password*."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return ``True`` when *plain* matches the stored *hashed* password."""
    if not plain or not hashed:
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False
