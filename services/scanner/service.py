"""Scanner service — find, claim, scan, persist."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import Engine, and_, delete, or_, update
from sqlmodel import Session, col, select

from core.clients.trivy import TrivyClient
from core.exceptions import ScanError
from core.models.database import CVE, FixStatus, Image, ImageCVE, ScanStatus, Severity
from core.models.trivy import ScanResult, VulnerabilityDetail
from services.scanner.settings import ScannerSettings

logger = logging.getLogger(__name__)


class ScannerService:
    def __init__(
        self, engine: Engine, trivy_client: TrivyClient, settings: ScannerSettings
    ) -> None:
        self.engine = engine
        self.trivy_client = trivy_client
        self.settings = settings

    # ------------------------------------------------------------------
    # Find & claim
    # ------------------------------------------------------------------

    def find_eligible_images(self) -> list[Image]:
        """Return up to batch_size images eligible for scanning."""
        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(seconds=self.settings.stale_timeout_seconds)
        rescan_cutoff = now - timedelta(seconds=self.settings.scan_interval_seconds)
        failed_cutoff = now - timedelta(seconds=self.settings.failed_retry_seconds)

        stmt = (
            select(Image)
            .where(
                Image.is_active == True,  # noqa: E712
                or_(
                    # Never scanned yet
                    Image.scan_status == ScanStatus.PENDING,
                    # Failed and backoff period has elapsed
                    and_(
                        Image.scan_status == ScanStatus.FAILED,
                        or_(
                            Image.scan_started_at == None,  # noqa: E711
                            Image.scan_started_at <= failed_cutoff,
                        ),
                    ),
                    # Stuck in scanning — claimed but never finished (stale lock)
                    and_(
                        Image.scan_status == ScanStatus.SCANNING,
                        or_(
                            Image.scan_started_at == None,  # noqa: E711
                            Image.scan_started_at <= stale_cutoff,
                        ),
                    ),
                    # Previously scanned and due for periodic rescan
                    and_(
                        Image.scan_status == ScanStatus.SCANNED,
                        Image.scanned_at != None,  # noqa: E711
                        Image.scanned_at <= rescan_cutoff,
                    ),
                ),
            )
            .limit(self.settings.batch_size)
        )

        with Session(self.engine) as session:
            return list(session.exec(stmt).all())

    def claim_image(self, image_id: int) -> bool:
        """Optimistic-lock claim — returns True if this scanner won the race."""
        now = datetime.now(timezone.utc)
        stale_cutoff = now - timedelta(seconds=self.settings.stale_timeout_seconds)

        stmt = (
            update(Image)
            .where(
                Image.id == image_id,
                or_(
                    Image.scan_status != ScanStatus.SCANNING,
                    Image.scan_started_at == None,  # noqa: E711
                    Image.scan_started_at <= stale_cutoff,
                ),
            )
            .values(scan_status=ScanStatus.SCANNING, scan_started_at=now)
        )

        with Session(self.engine) as session:
            result = session.exec(stmt)  # type: ignore[call-overload]
            session.commit()
            return result.rowcount > 0  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # Scan cycle
    # ------------------------------------------------------------------

    def run_cycle(self) -> None:
        """Sync entry point: loop batches until no eligible images remain."""
        while True:
            candidates = self.find_eligible_images()
            claimed = [
                img for img in candidates if self.claim_image(img.id)  # type: ignore[arg-type]
            ]
            if not claimed:
                logger.debug("No images to scan this cycle")
                return

            logger.info("Claimed %d images for scanning", len(claimed))
            asyncio.run(self._scan_batch(claimed))

    async def _scan_batch(self, images: list[Image]) -> None:
        await asyncio.gather(*(self.scan_one(img) for img in images))

    async def scan_one(self, image: Image) -> None:
        """Async Trivy call, then sync persist. On failure mark FAILED."""
        try:
            result = await self.trivy_client.scan(image.name, image.tag)
            self.persist_scan_result(image, result)
            logger.info(
                "Scanned %s:%s — %d vulns",
                image.name,
                image.tag,
                len(result.vulnerabilities),
            )
        except ScanError as exc:
            logger.error("Scan failed for %s:%s: %s", image.name, image.tag, exc)
            self._mark_failed(image)
        except (OSError, TimeoutError, ConnectionError) as exc:
            logger.warning(
                "Transient error scanning %s:%s (%s: %s) — will retry",
                image.name, image.tag, type(exc).__name__, exc,
            )
            self._mark_failed(image)
        except Exception as exc:
            logger.exception(
                "Unexpected error scanning %s:%s (%s: %s)",
                image.name, image.tag, type(exc).__name__, exc,
            )
            self._mark_failed(image)

    # ------------------------------------------------------------------
    # Persist
    # ------------------------------------------------------------------

    def persist_scan_result(self, image: Image, result: ScanResult) -> None:
        """Upsert CVEs + ImageCVEs, delete stale, update Image."""
        now = datetime.now(timezone.utc)

        with Session(self.engine) as session:
            session.exec(  # type: ignore[call-overload]
                update(Image)
                .where(Image.id == image.id)
                .values(
                    os_family=result.os_family,
                    os_version=result.os_version,
                    scan_status=ScanStatus.SCANNED,
                    scanned_at=now,
                    updated_at=now,
                )
            )

            seen_image_cve_ids: list[int] = []

            for vuln in result.vulnerabilities:
                cve = self._upsert_cve(session, vuln, now)
                image_cve = self._upsert_image_cve(session, image, cve, vuln)
                seen_image_cve_ids.append(image_cve.id)  # type: ignore[arg-type]

            # Delete stale ImageCVEs not in latest scan
            if seen_image_cve_ids:
                session.exec(  # type: ignore[call-overload]
                    delete(ImageCVE).where(
                        ImageCVE.image_id == image.id,
                        col(ImageCVE.id).notin_(seen_image_cve_ids),
                    )
                )
            else:
                session.exec(  # type: ignore[call-overload]
                    delete(ImageCVE).where(ImageCVE.image_id == image.id)
                )

            session.commit()

    def _mark_failed(self, image: Image) -> None:
        with Session(self.engine) as session:
            session.exec(  # type: ignore[call-overload]
                update(Image)
                .where(Image.id == image.id)
                .values(
                    scan_status=ScanStatus.FAILED,
                    updated_at=datetime.now(timezone.utc),
                )
            )
            session.commit()

    # ------------------------------------------------------------------
    # Upsert helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _upsert_cve(
        session: Session, vuln: VulnerabilityDetail, now: datetime
    ) -> CVE:
        cve = session.exec(
            select(CVE).where(CVE.cve_id == vuln.cve_id)
        ).first()

        severity = _parse_severity(vuln.severity)
        published_date = _parse_datetime(vuln.published_date)

        if cve is None:
            cve = CVE(
                cve_id=vuln.cve_id,
                severity=severity,
                cvss_score=vuln.cvss_score,
                title=vuln.title,
                description=vuln.description,
                published_date=published_date,
            )
            session.add(cve)
            session.flush()
        else:
            cve.severity = severity
            cve.cvss_score = vuln.cvss_score
            cve.title = vuln.title
            cve.description = vuln.description
            cve.published_date = published_date
            cve.updated_at = now
            session.add(cve)
            session.flush()

        return cve

    @staticmethod
    def _upsert_image_cve(
        session: Session, image: Image, cve: CVE, vuln: VulnerabilityDetail
    ) -> ImageCVE:
        image_cve = session.exec(
            select(ImageCVE).where(
                ImageCVE.image_id == image.id,
                ImageCVE.cve_id == cve.id,
                ImageCVE.package_name == vuln.package_name,
            )
        ).first()

        fix_status = _parse_fix_status(vuln.fix_status)

        if image_cve is None:
            image_cve = ImageCVE(
                image_id=image.id,  # type: ignore[arg-type]
                cve_id=cve.id,  # type: ignore[arg-type]
                package_name=vuln.package_name,
                installed_version=vuln.installed_version,
                fixed_version=vuln.fixed_version,
                fix_status=fix_status,
                pkg_class=vuln.pkg_class,
                pkg_type=vuln.pkg_type,
            )
            session.add(image_cve)
            session.flush()
        else:
            image_cve.installed_version = vuln.installed_version
            image_cve.fixed_version = vuln.fixed_version
            image_cve.fix_status = fix_status
            session.add(image_cve)
            session.flush()

        return image_cve


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------


def _parse_severity(value: str) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.UNKNOWN


def _parse_fix_status(value: str | None) -> FixStatus | None:
    if not value:
        return None
    try:
        return FixStatus(value)
    except ValueError:
        return None


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
