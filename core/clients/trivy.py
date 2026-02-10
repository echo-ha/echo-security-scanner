"""Async Trivy client — shells out to trivy CLI and parses JSON output."""

import asyncio
import json
import logging
from asyncio.subprocess import PIPE

from core.models.trivy import ScanResult, VulnerabilityDetail

logger = logging.getLogger(__name__)


class TrivyClient:
    async def scan(self, image_name: str, image_tag: str) -> ScanResult:
        """Run trivy image scan and return parsed result."""
        proc = await asyncio.create_subprocess_exec(
            "trivy", "image", "--format", "json", "--quiet",
            f"{image_name}:{image_tag}",
            stdout=PIPE, stderr=PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(
                f"Trivy scan failed for {image_name}:{image_tag}: "
                f"{stderr.decode()}"
            )

        raw = json.loads(stdout.decode())
        return self._parse_output(raw, image_name, image_tag)

    def _parse_output(
        self, raw: dict, image_name: str, image_tag: str
    ) -> ScanResult:
        metadata = raw.get("Metadata", {})
        os_info = metadata.get("OS", {})

        vulnerabilities: list[VulnerabilityDetail] = []
        for result in raw.get("Results", []):
            pkg_class = result.get("Class")
            pkg_type = result.get("Type")
            for vuln in result.get("Vulnerabilities") or []:
                cvss_score = self._extract_cvss_score(vuln)
                vulnerabilities.append(
                    VulnerabilityDetail(
                        cve_id=vuln["VulnerabilityID"],
                        severity=vuln.get("Severity", "UNKNOWN"),
                        cvss_score=cvss_score,
                        title=vuln.get("Title"),
                        description=vuln.get("Description"),
                        published_date=vuln.get("PublishedDate"),
                        package_name=vuln["PkgName"],
                        installed_version=vuln["InstalledVersion"],
                        fixed_version=vuln.get("FixedVersion") or None,
                        fix_status=vuln.get("Status"),
                        pkg_class=pkg_class,
                        pkg_type=pkg_type,
                    )
                )

        return ScanResult(
            image_name=image_name,
            image_tag=image_tag,
            os_family=os_info.get("Family"),
            os_version=os_info.get("Name"),
            vulnerabilities=vulnerabilities,
        )

    @staticmethod
    def _extract_cvss_score(vuln: dict) -> float | None:
        for source in vuln.get("CVSS", {}).values():
            if isinstance(source, dict) and "V3Score" in source:
                return source["V3Score"]
        return None
