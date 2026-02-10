from core.models.database import CVE, Image, ImageCVE
from core.models.trivy import ScanResult, VulnerabilityDetail

__all__ = ["Image", "CVE", "ImageCVE", "ScanResult", "VulnerabilityDetail"]
