"""Image-related endpoints."""

from fastapi import APIRouter, Query, Request

from core.models.database import Severity
from services.api.schemas import ImageCVEDetail, ImageSummary, PaginatedResponse

router = APIRouter(prefix="/api")


@router.get("/images")
def list_images(
    request: Request,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> PaginatedResponse[ImageSummary]:
    service = request.app.state.container.api_service()
    return service.list_images(offset=offset, limit=limit)


@router.get("/images/{image_name}/{tag}/cves")
def list_image_cves(
    request: Request,
    image_name: str,
    tag: str,
    severity: Severity | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> PaginatedResponse[ImageCVEDetail]:
    service = request.app.state.container.api_service()
    return service.list_image_cves(
        image_name=image_name,
        image_tag=tag,
        severity=severity,
        offset=offset,
        limit=limit,
    )
