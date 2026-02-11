"""Health check endpoint."""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlmodel import Session

from services.api.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=None)
def health(request: Request) -> HealthResponse | JSONResponse:
    try:
        engine = request.app.state.container.engine
        with Session(engine) as session:
            session.exec(text("SELECT 1"))  # type: ignore[call-overload]
        return HealthResponse(status="ok")
    except Exception:
        return JSONResponse(status_code=503, content={"status": "unavailable"})
