"""API composition root — owns the DB engine and wires dependencies."""

from sqlmodel import create_engine

from services.api.service import ApiService
from services.api.settings import ApiSettings


class ApiContainer:
    def __init__(self, settings: ApiSettings) -> None:
        self.settings = settings
        self.engine = create_engine(settings.db_url)

    def api_service(self) -> ApiService:
        return ApiService(self.engine)
