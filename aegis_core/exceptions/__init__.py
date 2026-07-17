class AegisError(Exception):
    """Base class for domain failures that are safe to map to generic API errors."""


class AuthenticationFailed(AegisError):
    pass


class AuthorizationFailed(AegisError):
    pass


class ConflictError(AegisError):
    pass


class NotFoundError(AegisError):
    pass


class ReplayDetected(AegisError):
    pass
