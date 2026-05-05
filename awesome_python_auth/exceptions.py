"""Custom exceptions for awesome-python-auth."""

from fastapi import HTTPException, status


class AuthError(Exception):
    """Base class for all authentication errors."""

    def __init__(self, message: str = "Authentication error") -> None:
        super().__init__(message)
        self.message = message


class NotAuthenticatedError(AuthError):
    """Raised when a request has no valid authentication credentials."""

    def __init__(self, message: str = "Not authenticated") -> None:
        super().__init__(message)


class ForbiddenError(AuthError):
    """Raised when the authenticated user lacks the required permissions."""

    def __init__(self, message: str = "Forbidden") -> None:
        super().__init__(message)


class InvalidTokenError(AuthError):
    """Raised when a JWT or temporary token cannot be verified."""

    def __init__(self, message: str = "Invalid token") -> None:
        super().__init__(message)


class CsrfError(AuthError):
    """Raised when the CSRF token is missing or invalid."""

    def __init__(self, message: str = "CSRF token invalid or missing") -> None:
        super().__init__(message)


def not_authenticated(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def forbidden(detail: str = "Forbidden") -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
