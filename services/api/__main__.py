"""Entry point for `python -m services.api`."""

import logging

import uvicorn
from fastapi import FastAPI

from core.exceptions import AppError
from services.api.container import ApiContainer
from services.api.exception_handlers import app_error_handler
from services.api.routes import cves, health, images
from services.api.settings import ApiSettings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_app() -> FastAPI:
    settings = ApiSettings()
    container = ApiContainer(settings)

    app = FastAPI(title="Echo Security Scanner API")

    app.add_exception_handler(AppError, app_error_handler)  # type: ignore[arg-type]

    app.state.container = container

    app.include_router(health.router)
    app.include_router(images.router)
    app.include_router(cves.router)

    return app


def main() -> None:
    settings = ApiSettings()
    logger.info("API starting on %s:%d", settings.host, settings.port)
    uvicorn.run(
        "services.api.__main__:create_app",
        host=settings.host,
        port=settings.port,
        factory=True,
    )


if __name__ == "__main__":
    main()
