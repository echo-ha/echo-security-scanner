"""Happy-path tests for the API service."""

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from core.exceptions import NotFoundError
from core.models.database import CVE, Image, ImageCVE, ScanStatus, Severity
from services.api.service import ApiService


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _engine():
    engine = create_engine("sqlite://", echo=False)
    SQLModel.metadata.create_all(engine)
    return engine


def _seed_image(session: Session, **overrides) -> Image:
    defaults: dict = {
        "name": "nginx",
        "tag": "1.19",
        "is_active": True,
        "scan_status": ScanStatus.SCANNED,
    }
    defaults.update(overrides)
    image = Image(**defaults)
    session.add(image)
    session.commit()
    session.refresh(image)
    return image


def _seed_cve(session: Session, **overrides) -> CVE:
    defaults: dict = {
        "cve_id": "CVE-2021-0001",
        "severity": Severity.HIGH,
        "cvss_score": 7.5,
        "title": "Test vuln",
    }
    defaults.update(overrides)
    cve = CVE(**defaults)
    session.add(cve)
    session.commit()
    session.refresh(cve)
    return cve


def _seed_image_cve(
    session: Session, image: Image, cve: CVE, **overrides
) -> ImageCVE:
    defaults: dict = {
        "image_id": image.id,
        "cve_id": cve.id,
        "package_name": "libtest",
        "installed_version": "1.0.0",
        "fixed_version": "1.0.1",
        "fix_status": "fixed",
        "pkg_class": "os-pkgs",
        "pkg_type": "debian",
    }
    defaults.update(overrides)
    image_cve = ImageCVE(**defaults)
    session.add(image_cve)
    session.commit()
    session.refresh(image_cve)
    return image_cve


# ------------------------------------------------------------------
# list_images
# ------------------------------------------------------------------


class TestListImages:
    def test_with_severity_counts(self):
        engine = _engine()
        with Session(engine) as s:
            img = _seed_image(s)
            cve_h = _seed_cve(s, cve_id="CVE-H", severity=Severity.HIGH)
            cve_c = _seed_cve(s, cve_id="CVE-C", severity=Severity.CRITICAL)
            _seed_image_cve(s, img, cve_h, package_name="pkg-a")
            _seed_image_cve(s, img, cve_c, package_name="pkg-b")

            img2 = _seed_image(s, name="alpine", tag="3.12")

        svc = ApiService(engine)
        result = svc.list_images()

        assert result.total == 2
        assert len(result.items) == 2

        nginx = next(i for i in result.items if i.name == "nginx")
        assert nginx.severity_counts.high == 1
        assert nginx.severity_counts.critical == 1
        assert nginx.total_cves == 2

        alpine = next(i for i in result.items if i.name == "alpine")
        assert alpine.total_cves == 0
        assert alpine.severity_counts.high == 0

    def test_pagination(self):
        engine = _engine()
        with Session(engine) as s:
            for i in range(5):
                _seed_image(s, name=f"img-{i}", tag="latest")

        svc = ApiService(engine)
        result = svc.list_images(offset=2, limit=2)

        assert result.total == 5
        assert len(result.items) == 2
        assert result.offset == 2
        assert result.limit == 2


# ------------------------------------------------------------------
# list_image_cves
# ------------------------------------------------------------------


class TestListImageCves:
    def test_returns_cves_with_package_details(self):
        engine = _engine()
        with Session(engine) as s:
            img = _seed_image(s)
            cve1 = _seed_cve(s, cve_id="CVE-A", severity=Severity.HIGH)
            cve2 = _seed_cve(s, cve_id="CVE-B", severity=Severity.LOW)
            _seed_image_cve(s, img, cve1, package_name="curl")
            _seed_image_cve(s, img, cve2, package_name="openssl")

        svc = ApiService(engine)
        result = svc.list_image_cves("nginx", "1.19")

        assert result.total == 2
        assert len(result.items) == 2
        assert all(item.package is not None for item in result.items)

    def test_severity_filter(self):
        engine = _engine()
        with Session(engine) as s:
            img = _seed_image(s)
            cve_h = _seed_cve(s, cve_id="CVE-H", severity=Severity.HIGH)
            cve_l = _seed_cve(s, cve_id="CVE-L", severity=Severity.LOW)
            _seed_image_cve(s, img, cve_h, package_name="curl")
            _seed_image_cve(s, img, cve_l, package_name="openssl")

        svc = ApiService(engine)
        result = svc.list_image_cves("nginx", "1.19", severity=Severity.HIGH)

        assert result.total == 1
        assert result.items[0].cve_id == "CVE-H"

    def test_not_found(self):
        engine = _engine()
        svc = ApiService(engine)

        with pytest.raises(NotFoundError):
            svc.list_image_cves("nonexistent", "latest")


# ------------------------------------------------------------------
# list_cves
# ------------------------------------------------------------------


class TestListCves:
    def test_returns_cves_with_affected_image_count(self):
        engine = _engine()
        with Session(engine) as s:
            img1 = _seed_image(s, name="nginx", tag="1.19")
            img2 = _seed_image(s, name="alpine", tag="3.12")
            cve = _seed_cve(s, cve_id="CVE-SHARED", severity=Severity.CRITICAL)
            _seed_image_cve(s, img1, cve, package_name="libssl")
            _seed_image_cve(s, img2, cve, package_name="libssl")

        svc = ApiService(engine)
        result = svc.list_cves()

        assert result.total == 1
        assert result.items[0].cve_id == "CVE-SHARED"
        assert result.items[0].affected_image_count == 2

    def test_severity_filter(self):
        engine = _engine()
        with Session(engine) as s:
            _seed_cve(s, cve_id="CVE-C", severity=Severity.CRITICAL)
            _seed_cve(s, cve_id="CVE-L", severity=Severity.LOW)

        svc = ApiService(engine)
        result = svc.list_cves(severity=Severity.CRITICAL)

        assert result.total == 1
        assert result.items[0].cve_id == "CVE-C"


# ------------------------------------------------------------------
# list_cve_images
# ------------------------------------------------------------------


class TestListCveImages:
    def test_returns_affected_images_with_package_details(self):
        engine = _engine()
        with Session(engine) as s:
            img1 = _seed_image(s, name="nginx", tag="1.19")
            img2 = _seed_image(s, name="postgres", tag="12")
            cve = _seed_cve(s, cve_id="CVE-MULTI")
            _seed_image_cve(s, img1, cve, package_name="libcurl")
            _seed_image_cve(s, img2, cve, package_name="libcurl")

        svc = ApiService(engine)
        result = svc.list_cve_images("CVE-MULTI")

        assert result.total == 2
        assert len(result.items) == 2
        names = {item.name for item in result.items}
        assert names == {"nginx", "postgres"}
        assert all(item.package.package_name == "libcurl" for item in result.items)

    def test_not_found(self):
        engine = _engine()
        svc = ApiService(engine)

        with pytest.raises(NotFoundError):
            svc.list_cve_images("CVE-NONEXISTENT")
