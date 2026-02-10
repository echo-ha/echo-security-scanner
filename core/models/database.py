"""SQLModel table definitions for the security scanner."""

from datetime import datetime, timezone
from enum import StrEnum

from sqlmodel import Field, Relationship, SQLModel, UniqueConstraint


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class ScanStatus(StrEnum):
    PENDING = "pending"
    SCANNING = "scanning"
    SCANNED = "scanned"
    FAILED = "failed"


class FixStatus(StrEnum):
    FIXED = "fixed"
    AFFECTED = "affected"
    WILL_NOT_FIX = "will_not_fix"
    FIX_DEFERRED = "fix_deferred"

class Image(SQLModel, table=True):
    """Scanned image. Also serves as scanner configuration — seeded from scanner_config.yaml, controlled via is_active."""

    __tablename__ = "images"
    __table_args__ = (UniqueConstraint("name", "tag"),)

    id: int | None = Field(default=None, primary_key=True)
    name: str
    tag: str
    is_active: bool = Field(default=True, index=True)
    os_family: str | None = None
    os_version: str | None = None
    scan_status: ScanStatus = Field(default=ScanStatus.PENDING)
    scan_started_at: datetime | None = None
    scanned_at: datetime | None = None
    last_scan_hash: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    image_cves: list["ImageCVE"] = Relationship(back_populates="image")


class CVE(SQLModel, table=True):
    __tablename__ = "cves"

    id: int | None = Field(default=None, primary_key=True)
    cve_id: str = Field(unique=True)
    severity: Severity
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    title: str | None = None
    description: str | None = None
    published_date: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    image_cves: list["ImageCVE"] = Relationship(back_populates="cve")


class ImageCVE(SQLModel, table=True):
    __tablename__ = "image_cves"
    __table_args__ = (UniqueConstraint("image_id", "cve_id", "package_name"),)

    id: int | None = Field(default=None, primary_key=True)
    image_id: int = Field(foreign_key="images.id", ondelete="CASCADE")
    cve_id: int = Field(foreign_key="cves.id", ondelete="CASCADE")
    package_name: str
    installed_version: str
    fixed_version: str | None = None
    fix_status: FixStatus | None = None
    pkg_class: str | None = None
    pkg_type: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    image: Image = Relationship(back_populates="image_cves")
    cve: CVE = Relationship(back_populates="image_cves")
