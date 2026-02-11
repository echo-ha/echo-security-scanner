"""Application exception hierarchy."""


class AppError(Exception):
    """Base application error."""

    def __init__(self, message: str, status_code: int = 500) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class NotFoundError(AppError):
    """Resource not found."""

    def __init__(self, message: str = "Resource not found") -> None:
        super().__init__(message, status_code=404)


class ScanError(AppError):
    """Trivy scan process failed (non-zero exit, bad output, etc.)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=500)
