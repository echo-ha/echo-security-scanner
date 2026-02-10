"""API service — read-only queries for the REST API."""

import logging

from sqlalchemy import Engine, case, distinct, func
from sqlmodel import Session, select

from core.exceptions import NotFoundError
from core.models.database import CVE, Image, ImageCVE, Severity
from services.api.schemas import (
    AffectedImage,
    CVESummary,
    ImageCVEDetail,
    ImageSummary,
    PackageDetail,
    PaginatedResponse,
    SeverityCounts,
)

logger = logging.getLogger(__name__)


class ApiService:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def list_images(
        self, offset: int = 0, limit: int = 50
    ) -> PaginatedResponse[ImageSummary]:
        """List all images with aggregated severity counts."""
        with Session(self.engine) as session:
            total = session.exec(
                select(func.count()).select_from(Image)
            ).one()

            stmt = (
                select(
                    Image.id,
                    Image.name,
                    Image.tag,
                    Image.os_family,
                    Image.os_version,
                    Image.scan_status,
                    Image.scanned_at,
                    func.count(case((CVE.severity == Severity.CRITICAL, 1))).label("critical"),
                    func.count(case((CVE.severity == Severity.HIGH, 1))).label("high"),
                    func.count(case((CVE.severity == Severity.MEDIUM, 1))).label("medium"),
                    func.count(case((CVE.severity == Severity.LOW, 1))).label("low"),
                    func.count(case((CVE.severity == Severity.UNKNOWN, 1))).label("unknown"),
                    func.count(ImageCVE.id).label("total_cves"),
                )
                .outerjoin(ImageCVE, Image.id == ImageCVE.image_id)
                .outerjoin(CVE, ImageCVE.cve_id == CVE.id)
                .group_by(Image.id)
                .order_by(Image.id)
                .offset(offset)
                .limit(limit)
            )

            rows = session.exec(stmt).all()  # type: ignore[call-overload]

            items = [
                ImageSummary(
                    id=row.id,
                    name=row.name,
                    tag=row.tag,
                    os_family=row.os_family,
                    os_version=row.os_version,
                    scan_status=row.scan_status,
                    scanned_at=row.scanned_at,
                    severity_counts=SeverityCounts(
                        critical=row.critical,
                        high=row.high,
                        medium=row.medium,
                        low=row.low,
                        unknown=row.unknown,
                    ),
                    total_cves=row.total_cves,
                )
                for row in rows
            ]

            return PaginatedResponse(
                items=items, total=total, offset=offset, limit=limit
            )

    def list_image_cves(
        self,
        image_name: str,
        image_tag: str,
        severity: Severity | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> PaginatedResponse[ImageCVEDetail]:
        """List CVEs for a specific image with optional severity filter."""
        with Session(self.engine) as session:
            image = session.exec(
                select(Image).where(Image.name == image_name, Image.tag == image_tag)
            ).first()

            if image is None:
                raise NotFoundError(f"Image {image_name}:{image_tag} not found")

            base_filter = [ImageCVE.image_id == image.id]
            if severity is not None:
                base_filter.append(CVE.severity == severity)

            count_stmt = (
                select(func.count())
                .select_from(ImageCVE)
                .join(CVE, ImageCVE.cve_id == CVE.id)
                .where(*base_filter)
            )
            total = session.exec(count_stmt).one()

            data_stmt = (
                select(CVE, ImageCVE)
                .join(ImageCVE, CVE.id == ImageCVE.cve_id)
                .where(*base_filter)
                .order_by(CVE.cve_id)
                .offset(offset)
                .limit(limit)
            )
            rows = session.exec(data_stmt).all()  # type: ignore[call-overload]

            items = [
                ImageCVEDetail(
                    cve_id=cve.cve_id,
                    severity=cve.severity,
                    cvss_score=cve.cvss_score,
                    title=cve.title,
                    description=cve.description,
                    published_date=cve.published_date,
                    package=PackageDetail(
                        package_name=image_cve.package_name,
                        installed_version=image_cve.installed_version,
                        fixed_version=image_cve.fixed_version,
                        fix_status=image_cve.fix_status,
                        pkg_class=image_cve.pkg_class,
                        pkg_type=image_cve.pkg_type,
                    ),
                )
                for cve, image_cve in rows
            ]

            return PaginatedResponse(
                items=items, total=total, offset=offset, limit=limit
            )

    def list_cves(
        self,
        severity: Severity | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> PaginatedResponse[CVESummary]:
        """List all unique CVEs with affected image count."""
        with Session(self.engine) as session:
            base_filter = []
            if severity is not None:
                base_filter.append(CVE.severity == severity)

            count_stmt = select(func.count()).select_from(CVE)
            if base_filter:
                count_stmt = count_stmt.where(*base_filter)
            total = session.exec(count_stmt).one()

            data_stmt = (
                select(
                    CVE.cve_id,
                    CVE.severity,
                    CVE.cvss_score,
                    CVE.title,
                    CVE.description,
                    CVE.published_date,
                    func.count(distinct(ImageCVE.image_id)).label("affected_image_count"),
                )
                .outerjoin(ImageCVE, CVE.id == ImageCVE.cve_id)
                .group_by(CVE.id)
                .order_by(CVE.cve_id)
                .offset(offset)
                .limit(limit)
            )
            if base_filter:
                data_stmt = data_stmt.where(*base_filter)

            rows = session.exec(data_stmt).all()  # type: ignore[call-overload]

            items = [
                CVESummary(
                    cve_id=row.cve_id,
                    severity=row.severity,
                    cvss_score=row.cvss_score,
                    title=row.title,
                    description=row.description,
                    published_date=row.published_date,
                    affected_image_count=row.affected_image_count,
                )
                for row in rows
            ]

            return PaginatedResponse(
                items=items, total=total, offset=offset, limit=limit
            )

    def list_cve_images(
        self, cve_id: str, offset: int = 0, limit: int = 50
    ) -> PaginatedResponse[AffectedImage]:
        """List all images affected by a specific CVE."""
        with Session(self.engine) as session:
            cve = session.exec(
                select(CVE).where(CVE.cve_id == cve_id)
            ).first()

            if cve is None:
                raise NotFoundError(f"CVE {cve_id} not found")

            count_stmt = (
                select(func.count())
                .select_from(ImageCVE)
                .where(ImageCVE.cve_id == cve.id)
            )
            total = session.exec(count_stmt).one()

            data_stmt = (
                select(Image, ImageCVE)
                .join(ImageCVE, Image.id == ImageCVE.image_id)
                .where(ImageCVE.cve_id == cve.id)
                .order_by(Image.id)
                .offset(offset)
                .limit(limit)
            )
            rows = session.exec(data_stmt).all()  # type: ignore[call-overload]

            items = [
                AffectedImage(
                    image_id=image.id,  # type: ignore[arg-type]
                    name=image.name,
                    tag=image.tag,
                    scan_status=image.scan_status,
                    scanned_at=image.scanned_at,
                    package=PackageDetail(
                        package_name=image_cve.package_name,
                        installed_version=image_cve.installed_version,
                        fixed_version=image_cve.fixed_version,
                        fix_status=image_cve.fix_status,
                        pkg_class=image_cve.pkg_class,
                        pkg_type=image_cve.pkg_type,
                    ),
                )
                for image, image_cve in rows
            ]

            return PaginatedResponse(
                items=items, total=total, offset=offset, limit=limit
            )
