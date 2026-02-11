"""APScheduler entry point — runs scan cycles every 15 minutes."""

import logging

from apscheduler.schedulers.blocking import BlockingScheduler
from sqlmodel import SQLModel

from services.scanner.container import ScannerContainer
from services.scanner.settings import ScannerSettings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main() -> None:
    settings = ScannerSettings()
    container = ScannerContainer(settings)
    SQLModel.metadata.create_all(container.engine)

    service = container.scanner_service()
    scheduler = BlockingScheduler()

    scheduler.add_job(
        service.run_cycle,
        "interval",
        seconds=settings.scan_interval_seconds,
        id="scan_cycle",
    )

    # Run once immediately on startup, then every interval
    service.run_cycle()

    logger.info("Scanner scheduled every %ds", settings.scan_interval_seconds)
    scheduler.start()


if __name__ == "__main__":
    main()
