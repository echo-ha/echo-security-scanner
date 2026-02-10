"""CVE-related endpoints."""

from fastapi import APIRouter, Query, Request

from core.models.database import Severity
from services.api.schemas import AffectedImage, CVESummary, PaginatedResponse

router = APIRouter(prefix="/api")


@router.get("/cves")
def list_cves(
    request: Request,
    severity: Severity | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> PaginatedResponse[CVESummary]:
    service = request.app.state.container.api_service()
    return service.list_cves(severity=severity, offset=offset, limit=limit)


@router.get("/cves/{cve_id}/images")
def list_cve_images(
    request: Request,
    cve_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> PaginatedResponse[AffectedImage]:
    service = request.app.state.container.api_service()
    return service.list_cve_images(cve_id=cve_id, offset=offset, limit=limit)
