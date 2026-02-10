"""Scanner composition root — owns the DB engine and wires dependencies."""

from sqlmodel import create_engine

from core.clients.trivy import TrivyClient
from services.scanner.service import ScannerService
from services.scanner.settings import ScannerSettings


class ScannerContainer:
    def __init__(self, settings: ScannerSettings) -> None:
        self.settings = settings
        self.engine = create_engine(settings.db_url)
        self.trivy_client = TrivyClient()

    def scanner_service(self) -> ScannerService:
        return ScannerService(self.engine, self.trivy_client, self.settings)
