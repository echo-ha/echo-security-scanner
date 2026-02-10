"""Pydantic response schemas for the REST API."""

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class HealthResponse(BaseModel):
    status: str


class SeverityCounts(BaseModel):
    """CVE count breakdown by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0


class ImageSummary(BaseModel):
    """Image with aggregated CVE severity counts."""

    id: int
    name: str
    tag: str
    os_family: str | None
    os_version: str | None
    scan_status: str
    scanned_at: datetime | None
    severity_counts: SeverityCounts
    total_cves: int


class PackageDetail(BaseModel):
    """Package-level vulnerability detail."""

    package_name: str
    installed_version: str
    fixed_version: str | None
    fix_status: str | None
    pkg_class: str | None
    pkg_type: str | None


class CVESummary(BaseModel):
    """A CVE with affected image count — for GET /api/cves."""

    cve_id: str
    severity: str
    cvss_score: float | None
    title: str | None
    description: str | None
    published_date: datetime | None
    affected_image_count: int


class ImageCVEDetail(BaseModel):
    """A CVE with package details — for GET /api/images/{name}/{tag}/cves."""

    cve_id: str
    severity: str
    cvss_score: float | None
    title: str | None
    description: str | None
    published_date: datetime | None
    package: PackageDetail


class AffectedImage(BaseModel):
    """Image affected by a CVE, including the relevant package info."""

    image_id: int
    name: str
    tag: str
    scan_status: str
    scanned_at: datetime | None
    package: PackageDetail


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated list wrapper."""

    items: list[T]
    total: int
    offset: int
    limit: int
