# Findings from Warmup Analysis

## Domain Pydantic Models (from Trivy output)

We define slim domain models capturing only the fields we extract. The `TrivyClient` is the only place that knows Trivy's JSON structure and translates it into these models.

```python
from pydantic import BaseModel


class VulnerabilityDetail(BaseModel):
    """A single vulnerability extracted from a Trivy scan result."""
    cve_id: str
    severity: str
    package_name: str
    installed_version: str
    fixed_version: str | None = None
    description: str | None = None


class ScanResult(BaseModel):
    """Parsed output of a Trivy image scan -- our domain model, not Trivy's schema."""
    image_name: str
    image_tag: str
    vulnerabilities: list[VulnerabilityDetail]
```

## Trivy JSON Parsing Logic

```python
def parse_trivy_output(raw: dict) -> ScanResult:
    """Translate raw Trivy JSON into our domain model. This logic lives in TrivyClient."""
    artifact = raw["ArtifactName"]
    parts = artifact.rsplit(":", 1)
    name = parts[0]
    tag = parts[1] if len(parts) > 1 else "latest"

    vulns = []
    for result in raw.get("Results") or []:
        for v in result.get("Vulnerabilities") or []:
            vulns.append(VulnerabilityDetail(
                cve_id=v["VulnerabilityID"],
                severity=v.get("Severity", "UNKNOWN"),
                package_name=v["PkgName"],
                installed_version=v["InstalledVersion"],
                fixed_version=v.get("FixedVersion"),
                description=v.get("Title"),
            ))

    return ScanResult(image_name=name, image_tag=tag, vulnerabilities=vulns)
```
