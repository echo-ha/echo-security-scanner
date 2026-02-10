"""Happy-path tests for the scanner service."""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

from sqlmodel import Session, SQLModel, create_engine, select

from core.clients.trivy import TrivyClient
from core.models.database import CVE, Image, ImageCVE, ScanStatus
from core.models.trivy import ScanResult, VulnerabilityDetail
from services.scanner.service import ScannerService
from services.scanner.settings import ScannerSettings


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _engine():
    engine = create_engine("sqlite://", echo=False)
    SQLModel.metadata.create_all(engine)
    return engine


def _settings(**overrides) -> ScannerSettings:
    defaults = {
        "db_url": "sqlite://",
        "scan_interval_seconds": 900,
        "stale_timeout_seconds": 600,
        "failed_retry_seconds": 300,
        "batch_size": 5,
    }
    defaults.update(overrides)
    return ScannerSettings(**defaults)


def _scan_result(
    image_name: str = "nginx",
    image_tag: str = "1.19",
    vulns: list[VulnerabilityDetail] | None = None,
) -> ScanResult:
    if vulns is None:
        vulns = [
            VulnerabilityDetail(
                cve_id="CVE-2021-0001",
                severity="HIGH",
                cvss_score=7.5,
                title="Test vuln",
                description="A test vulnerability",
                published_date="2021-01-01T00:00:00Z",
                package_name="libtest",
                installed_version="1.0.0",
                fixed_version="1.0.1",
                fix_status="fixed",
                pkg_class="os-pkgs",
                pkg_type="debian",
            ),
        ]
    return ScanResult(
        image_name=image_name,
        image_tag=image_tag,
        os_family="debian",
        os_version="10.9",
        vulnerabilities=vulns,
    )


def _seed(session: Session, **overrides) -> Image:
    defaults: dict = {
        "name": "nginx",
        "tag": "1.19",
        "is_active": True,
        "scan_status": ScanStatus.PENDING,
    }
    defaults.update(overrides)
    image = Image(**defaults)
    session.add(image)
    session.commit()
    session.refresh(image)
    session.expunge(image)
    return image


# ------------------------------------------------------------------
# find_eligible_images
# ------------------------------------------------------------------


class TestFindEligibleImages:
    def test_finds_pending(self):
        engine = _engine()
        with Session(engine) as s:
            _seed(s)

        svc = ScannerService(engine, TrivyClient(), _settings())
        result = svc.find_eligible_images()
        assert len(result) == 1
        assert result[0].scan_status == ScanStatus.PENDING

    def test_finds_failed_after_backoff(self):
        engine = _engine()
        with Session(engine) as s:
            _seed(
                s,
                scan_status=ScanStatus.FAILED,
                scan_started_at=datetime.now(timezone.utc) - timedelta(seconds=600),
            )

        svc = ScannerService(engine, TrivyClient(), _settings(failed_retry_seconds=300))
        assert len(svc.find_eligible_images()) == 1

    def test_skips_recently_failed(self):
        engine = _engine()
        with Session(engine) as s:
            _seed(
                s,
                scan_status=ScanStatus.FAILED,
                scan_started_at=datetime.now(timezone.utc) - timedelta(seconds=60),
            )

        svc = ScannerService(engine, TrivyClient(), _settings(failed_retry_seconds=300))
        assert len(svc.find_eligible_images()) == 0

    def test_finds_stale_scanning(self):
        engine = _engine()
        with Session(engine) as s:
            _seed(
                s,
                scan_status=ScanStatus.SCANNING,
                scan_started_at=datetime.now(timezone.utc) - timedelta(seconds=1200),
            )

        svc = ScannerService(engine, TrivyClient(), _settings(stale_timeout_seconds=600))
        assert len(svc.find_eligible_images()) == 1

    def test_finds_due_for_rescan(self):
        engine = _engine()
        with Session(engine) as s:
            _seed(
                s,
                scan_status=ScanStatus.SCANNED,
                scanned_at=datetime.now(timezone.utc) - timedelta(seconds=1800),
            )

        svc = ScannerService(engine, TrivyClient(), _settings(scan_interval_seconds=900))
        assert len(svc.find_eligible_images()) == 1

    def test_skips_inactive(self):
        engine = _engine()
        with Session(engine) as s:
            _seed(s, is_active=False)

        svc = ScannerService(engine, TrivyClient(), _settings())
        assert len(svc.find_eligible_images()) == 0

    def test_skips_recently_scanned(self):
        engine = _engine()
        with Session(engine) as s:
            _seed(
                s,
                scan_status=ScanStatus.SCANNED,
                scanned_at=datetime.now(timezone.utc) - timedelta(seconds=60),
            )

        svc = ScannerService(engine, TrivyClient(), _settings(scan_interval_seconds=900))
        assert len(svc.find_eligible_images()) == 0

    def test_respects_batch_size(self):
        engine = _engine()
        with Session(engine) as s:
            for i in range(10):
                _seed(s, name=f"img-{i}", tag="latest")

        svc = ScannerService(engine, TrivyClient(), _settings(batch_size=3))
        assert len(svc.find_eligible_images()) == 3


# ------------------------------------------------------------------
# claim_image
# ------------------------------------------------------------------


class TestClaimImage:
    def test_claim_success(self):
        engine = _engine()
        with Session(engine) as s:
            image = _seed(s)

        svc = ScannerService(engine, TrivyClient(), _settings())
        assert svc.claim_image(image.id) is True

        with Session(engine) as s:
            img = s.get(Image, image.id)
            assert img is not None
            assert img.scan_status == ScanStatus.SCANNING
            assert img.scan_started_at is not None

    def test_claim_fails_if_already_scanning(self):
        engine = _engine()
        with Session(engine) as s:
            image = _seed(
                s,
                scan_status=ScanStatus.SCANNING,
                scan_started_at=datetime.now(timezone.utc),
            )

        svc = ScannerService(engine, TrivyClient(), _settings())
        assert svc.claim_image(image.id) is False

    def test_claim_succeeds_for_stale_scanning(self):
        engine = _engine()
        with Session(engine) as s:
            image = _seed(
                s,
                scan_status=ScanStatus.SCANNING,
                scan_started_at=datetime.now(timezone.utc) - timedelta(seconds=1200),
            )

        svc = ScannerService(engine, TrivyClient(), _settings(stale_timeout_seconds=600))
        assert svc.claim_image(image.id) is True


# ------------------------------------------------------------------
# persist_scan_result
# ------------------------------------------------------------------


class TestPersistScanResult:
    def test_skips_upsert_when_hash_unchanged(self):
        engine = _engine()
        with Session(engine) as s:
            image = _seed(s, scan_status=ScanStatus.SCANNING)

        svc = ScannerService(engine, TrivyClient(), _settings())
        result = _scan_result()

        # First persist — full upsert
        svc.persist_scan_result(image, result)

        with Session(engine) as s:
            img = s.get(Image, image.id)
            assert img is not None
            first_hash = img.last_scan_hash
            assert first_hash is not None
            first_scanned_at = img.scanned_at
            s.expunge(img)

        # Second persist with same result — should skip upsert, just bump timestamp
        svc.persist_scan_result(img, result)

        with Session(engine) as s:
            img2 = s.get(Image, image.id)
            assert img2 is not None
            assert img2.last_scan_hash == first_hash
            assert img2.scanned_at is not None
            assert img2.scanned_at >= first_scanned_at  # type: ignore[operator]
            assert len(list(s.exec(select(CVE)).all())) == 1
            assert len(list(s.exec(select(ImageCVE)).all())) == 1

    def test_creates_cves_and_image_cves(self):
        engine = _engine()
        with Session(engine) as s:
            image = _seed(s, scan_status=ScanStatus.SCANNING)

        svc = ScannerService(engine, TrivyClient(), _settings())
        svc.persist_scan_result(image, _scan_result())

        with Session(engine) as s:
            img = s.get(Image, image.id)
            assert img is not None
            assert img.scan_status == ScanStatus.SCANNED
            assert img.os_family == "debian"
            assert img.scanned_at is not None

            cves = list(s.exec(select(CVE)).all())
            assert len(cves) == 1
            assert cves[0].cve_id == "CVE-2021-0001"

            image_cves = list(s.exec(select(ImageCVE)).all())
            assert len(image_cves) == 1
            assert image_cves[0].package_name == "libtest"

    def test_removes_stale_image_cves(self):
        engine = _engine()
        with Session(engine) as s:
            image = _seed(s, scan_status=ScanStatus.SCANNING)

            # Pre-existing CVE + ImageCVE that won't appear in the new scan
            old_cve = CVE(cve_id="CVE-OLD-0001", severity="LOW")
            s.add(old_cve)
            s.flush()
            old_image_cve = ImageCVE(
                image_id=image.id,
                cve_id=old_cve.id,
                package_name="old-pkg",
                installed_version="0.1",
            )
            s.add(old_image_cve)
            s.commit()

        svc = ScannerService(engine, TrivyClient(), _settings())
        svc.persist_scan_result(image, _scan_result())

        with Session(engine) as s:
            image_cves = list(
                s.exec(select(ImageCVE).where(ImageCVE.image_id == image.id)).all()
            )
            assert len(image_cves) == 1
            assert image_cves[0].package_name == "libtest"


# ------------------------------------------------------------------
# scan_one
# ------------------------------------------------------------------


class TestScanOne:
    def test_success(self):
        engine = _engine()
        with Session(engine) as s:
            image = _seed(s, scan_status=ScanStatus.SCANNING)

        mock_client = TrivyClient()
        mock_client.scan = AsyncMock(return_value=_scan_result())  # type: ignore[method-assign]

        svc = ScannerService(engine, mock_client, _settings())
        asyncio.run(svc.scan_one(image))

        with Session(engine) as s:
            img = s.get(Image, image.id)
            assert img is not None
            assert img.scan_status == ScanStatus.SCANNED

    def test_failure_marks_failed(self):
        engine = _engine()
        with Session(engine) as s:
            image = _seed(s, scan_status=ScanStatus.SCANNING)

        mock_client = TrivyClient()
        mock_client.scan = AsyncMock(side_effect=RuntimeError("trivy crashed"))  # type: ignore[method-assign]

        svc = ScannerService(engine, mock_client, _settings())
        asyncio.run(svc.scan_one(image))

        with Session(engine) as s:
            img = s.get(Image, image.id)
            assert img is not None
            assert img.scan_status == ScanStatus.FAILED


# ------------------------------------------------------------------
# run_cycle
# ------------------------------------------------------------------


class TestRunCycle:
    def test_scans_batch(self):
        engine = _engine()
        with Session(engine) as s:
            for i in range(3):
                _seed(s, name=f"img-{i}", tag="latest")

        mock_client = TrivyClient()
        mock_client.scan = AsyncMock(  # type: ignore[method-assign]
            side_effect=lambda name, tag: _scan_result(image_name=name, image_tag=tag)
        )

        svc = ScannerService(engine, mock_client, _settings())
        svc.run_cycle()

        with Session(engine) as s:
            images = list(s.exec(select(Image)).all())
            assert all(img.scan_status == ScanStatus.SCANNED for img in images)
        assert mock_client.scan.call_count == 3
