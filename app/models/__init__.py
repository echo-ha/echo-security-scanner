from app.models.database import CVE, Image, ImageCVE
from app.models.trivy import ScanResult, VulnerabilityDetail

__all__ = ["Image", "CVE", "ImageCVE", "ScanResult", "VulnerabilityDetail"]
