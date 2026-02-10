# Models Layer Plan

## Context

First implementation step for the security scanner. Two model groups needed:
- **`trivy.py`** -- Pydantic models for parsing Trivy JSON output
- **`database.py`** -- SQLModel tables (Image, CVE, ImageCVE) using `create_all()`

## trivy.py -- Trivy Parsing Models

Pure Pydantic `BaseModel`. Not DB tables. These must capture **everything** we need to populate the DB tables from a single Trivy scan.

### Mapping: Trivy JSON field -> our model field -> DB column

| Trivy JSON path | Model field | Ends up in DB table |
|---|---|---|
| `ArtifactName` (split on `:`) | `ScanResult.image_name/image_tag` | images.name, images.tag |
| `Metadata.OS.Family` | `ScanResult.os_family` | images.os_family |
| `Metadata.OS.Name` | `ScanResult.os_version` | images.os_version |
| `Results[].Class` | `VulnerabilityDetail.pkg_class` | image_cves.pkg_class |
| `Results[].Type` | `VulnerabilityDetail.pkg_type` | image_cves.pkg_type |
| `Vulnerabilities[].VulnerabilityID` | `VulnerabilityDetail.cve_id` | cves.cve_id |
| `Vulnerabilities[].Severity` | `VulnerabilityDetail.severity` | cves.severity |
| `Vulnerabilities[].CVSS.*.V3Score` | `VulnerabilityDetail.cvss_score` | cves.cvss_score |
| `Vulnerabilities[].Title` | `VulnerabilityDetail.title` | cves.title |
| `Vulnerabilities[].Description` | `VulnerabilityDetail.description` | cves.description |
| `Vulnerabilities[].PublishedDate` | `VulnerabilityDetail.published_date` | cves.published_date |
| `Vulnerabilities[].PkgName` | `VulnerabilityDetail.package_name` | image_cves.package_name |
| `Vulnerabilities[].InstalledVersion` | `VulnerabilityDetail.installed_version` | image_cves.installed_version |
| `Vulnerabilities[].FixedVersion` | `VulnerabilityDetail.fixed_version` | image_cves.fixed_version |
| `Vulnerabilities[].Status` | `VulnerabilityDetail.fix_status` | image_cves.fix_status |

```python
class VulnerabilityDetail(BaseModel):
    """One vulnerability from Trivy output, carrying all fields needed for both CVE and ImageCVE tables."""
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
    pkg_class: str | None = None     # "os-pkgs" or "lang-pkgs"
    pkg_type: str | None = None      # "debian", "alpine", "python-pkg", etc.

class ScanResult(BaseModel):
    """Full parsed Trivy scan -- everything needed to update images + cves + image_cves."""
    image_name: str
    image_tag: str
    os_family: str | None = None
    os_version: str | None = None
    vulnerabilities: list[VulnerabilityDetail]
```

Note: `pkg_class` and `pkg_type` come from the Result level (not the Vulnerability level) in Trivy's JSON, so the parsing logic must propagate them down into each VulnerabilityDetail.

## database.py -- SQLModel Tables

### Image (one row per scanned image)

| Column | Type | Notes |
|--------|------|-------|
| id | int, PK | auto-increment |
| name | str | e.g. "nginx" |
| tag | str | e.g. "1.19" |
| os_family | str, nullable | e.g. "debian", "alpine" |
| os_version | str, nullable | e.g. "10.9" |
| scan_status | str | "pending", "scanning", "scanned", "failed" |
| scanned_at | datetime, nullable | last successful scan |
| created_at | datetime | auto |
| updated_at | datetime | auto |

Unique constraint: (name, tag)

### CVE (one row per unique CVE, shared across images)

| Column | Type | Notes |
|--------|------|-------|
| id | int, PK | auto-increment |
| cve_id | str, unique | e.g. "CVE-2022-32221" |
| severity | str | CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN |
| cvss_score | float, nullable | 0.0-10.0 |
| title | str, nullable | short description |
| description | str, nullable | full text |
| published_date | datetime, nullable | from Trivy |
| created_at | datetime | auto |
| updated_at | datetime | auto |

### ImageCVE (junction table -- the many-to-many link)

| Column | Type | Notes |
|--------|------|-------|
| id | int, PK | auto-increment |
| image_id | int, FK -> images | CASCADE delete |
| cve_id | int, FK -> cves | CASCADE delete |
| package_name | str | e.g. "curl" |
| installed_version | str | e.g. "7.64.0-4+deb10u2" |
| fixed_version | str, nullable | e.g. "7.64.0-4+deb10u4" |
| fix_status | str | "fixed", "affected", "will_not_fix", "fix_deferred" |
| pkg_class | str, nullable | "os-pkgs" or "lang-pkgs" |
| pkg_type | str, nullable | "debian", "alpine", "python-pkg", etc. |
| created_at | datetime | auto |

Unique constraint: (image_id, cve_id, package_name)

## Relationship Diagram

```
images              image_cves              cves
+------------+      +-------------------+   +------------+
| id (PK)    |<──┐  | id (PK)           |   | id (PK)    |
| name       |   └──| image_id (FK)     |   | cve_id     |
| tag        |      | cve_id (FK)    |──>   | severity   |
| os_family  |      | package_name      |   | cvss_score |
| os_version |      | installed_version |   | title      |
| scan_status|      | fixed_version     |   | description|
| scanned_at |      | fix_status        |   | published  |
+------------+      +-------------------+   +------------+
```

**Why CVEs are shared:** Same CVE-2022-37434 in zlib affects both nginx:1.19 and alpine:3.12.
Each gets its own ImageCVE row with its own installed_version/fixed_version.

## Enums (app/core/enums.py)

`Severity`, `ScanStatus`, `FixStatus` as `StrEnum`. Validation at Python level, stored as varchar.

## Files to Create

1. `app/__init__.py`
2. `app/models/__init__.py`
3. `app/models/trivy.py`
4. `app/models/database.py`
5. `app/core/__init__.py`
6. `app/core/enums.py`
