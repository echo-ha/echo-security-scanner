"""Entry point for `python -m services.scanner`."""

import logging
import time

from sqlmodel import SQLModel

from services.scanner.container import ScannerContainer
from services.scanner.settings import ScannerSettings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main() -> None:
    settings = ScannerSettings()
    container = ScannerContainer(settings)

    SQLModel.metadata.create_all(container.engine)
    logger.info("Scanner starting (interval=%ds)", settings.scan_interval_seconds)

    service = container.scanner_service()
    while True:
        try:
            service.run_cycle()
        except Exception:
            logger.exception("Scan cycle failed")
        time.sleep(settings.scan_interval_seconds)


if __name__ == "__main__":
    main()
