"""Pydantic models for parsing Trivy JSON output."""

from pydantic import BaseModel


class VulnerabilityDetail(BaseModel):
    """One vulnerability from Trivy output, carrying fields for both CVE and ImageCVE tables."""

    # -> cves table
    cve_id: str
    severity: str
    cvss_score: float | None = None
    title: str | None = None
    description: str | None = None
    published_date: str | None = None
    # -> image_cves table
    package_name: str
    installed_version: str
    fixed_version: str | None = None
    fix_status: str | None = None
    pkg_class: str | None = None  # "os-pkgs" or "lang-pkgs"
    pkg_type: str | None = None  # "debian", "alpine", "python-pkg", etc.


class ScanResult(BaseModel):
    """Full parsed Trivy scan -- everything needed to populate images + cves + image_cves."""

    image_name: str
    image_tag: str
    os_family: str | None = None
    os_version: str | None = None
    vulnerabilities: list[VulnerabilityDetail]
