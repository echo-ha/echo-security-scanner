"""FastAPI exception handlers."""

from fastapi import Request
from fastapi.responses import JSONResponse

from core.exceptions import AppError


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    """Handle all AppError subclasses."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message},
    )
