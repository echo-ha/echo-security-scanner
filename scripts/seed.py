"""Create tables and seed the Image table with the required container images."""

import logging
import os

from sqlmodel import Session, SQLModel, create_engine, select

from core.models.database import Image

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

IMAGES = [
    ("nginx", "1.19"),
    ("postgres", "12"),
    ("redis", "6.0"),
    ("node", "14-alpine"),
    ("python", "3.8-slim"),
    ("alpine", "3.12"),
    ("ubuntu", "20.04"),
    ("mysql", "8.0"),
    ("mongo", "4.4"),
    ("httpd", "2.4"),
]


def seed() -> None:
    db_url = os.environ.get(
        "SCANNER_DB_URL", "postgresql://scanner:scanner@localhost:5432/scanner"
    )
    engine = create_engine(db_url)

    logger.info("Creating tables...")
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        existing = {
            (img.name, img.tag)
            for img in session.exec(select(Image)).all()
        }

        added = 0
        for name, tag in IMAGES:
            if (name, tag) not in existing:
                session.add(Image(name=name, tag=tag))
                added += 1

        session.commit()
        logger.info("Seeded %d new images (%d already existed)", added, len(existing))


if __name__ == "__main__":
    seed()
